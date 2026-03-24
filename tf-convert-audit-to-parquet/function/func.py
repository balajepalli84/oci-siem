import io
import json
import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import duckdb
import oci
from fdk import response

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

PARQUET_BUCKET    = os.environ.get("PARQUET_BUCKET", "Parquet_Security_Lake_Audit_Logs")
PARQUET_NAMESPACE = os.environ.get("PARQUET_NAMESPACE", "ociateam")
LOG_SOURCE        = os.environ.get("LOG_SOURCE", "audit")


# ── Auth ──────────────────────────────────────────────────────────────────────

def get_os_client():
    signer = oci.auth.signers.get_resource_principals_signer()
    return oci.object_storage.ObjectStorageClient(config={}, signer=signer)


# ── Event parsing ─────────────────────────────────────────────────────────────

def parse_event(body: dict) -> tuple[str, str, str]:
    """
    OCI Events payload for Object Storage ObjectCreated:
    {
      "data": {
        "additionalDetails": { "namespace": "...", "bucketName": "..." },
        "resourceName": "<connector-ocid>/20260324T021117Z_20260324T021832Z.0.log.gz"
      }
    }
    """
    details   = body["data"]["additionalDetails"]
    namespace = details["namespace"]
    bucket    = details["bucketName"]
    obj_name  = body["data"]["resourceName"]
    return namespace, bucket, obj_name


# ── Partition inference ───────────────────────────────────────────────────────

def infer_partition(obj_name: str, source: str = "audit") -> str:
    """
    SCH writes files as:
      <connector-ocid>/20260324T021117Z_20260324T021832Z.0.log.gz

    Parse the start timestamp from the filename to build the partition path:
      logs/{source}/{yyyy}/{MM}/{dd}/{HH}/

    Falls back to current UTC hour if parsing fails — data is never lost,
    just placed in the correct hour partition on retry.
    """
    try:
        filename = Path(obj_name).name       # 20260324T021117Z_20260324T021832Z.0.log.gz
        ts_str   = filename.split("_")[0]    # 20260324T021117Z
        ts       = datetime.strptime(ts_str, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        return f"logs/{source}/{ts.year}/{ts.month:02d}/{ts.day:02d}/{ts.hour:02d}"
    except Exception:
        ts = datetime.now(timezone.utc)
        logger.warning(f"Could not parse timestamp from '{obj_name}', falling back to current UTC hour")
        return f"logs/{source}/{ts.year}/{ts.month:02d}/{ts.day:02d}/{ts.hour:02d}"


# ── Core conversion ───────────────────────────────────────────────────────────

def convert(raw_path: str, parquet_path: str) -> int:
    """
    OCI log envelope written by SCH:
    [
      {
        "datetime": "2026-03-23T14:00:01.123Z",
        "logContent": {
          "id":      "...",
          "type":    "com.oraclecloud.audit.action",
          "source":  "...",
          "subject": "...",
          "data":    { ...actual log payload... },
          "oracle":  { "tenantid": "...", "compartmentid": "..." }
        }
      }
    ]

    logContent is typed explicitly as JSON so DuckDB never auto-detects its
    internal struct. This avoids the duplicate key error on HTTP header fields
    (e.g. accept-language) without dropping any rows.

    Fields are extracted via JSON path operators at SELECT time.
    log_data is kept as a raw JSON string so the schema stays flexible
    across audit and flow log shapes.
    """
    con = duckdb.connect()
    try:
        con.execute(f"""
            CREATE OR REPLACE TABLE raw AS
            SELECT
                "datetime"                              AS event_time,
                logContent->>'$.type'                   AS log_type,
                logContent->>'$.source'                 AS log_source,
                logContent->>'$.subject'                AS log_subject,
                logContent->>'$.id'                     AS log_id,
                logContent->>'$.oracle.tenantid'        AS tenant_id,
                logContent->>'$.oracle.compartmentid'   AS compartment_id,
                logContent->>'$.data'                   AS log_data
            FROM read_json(
                '{raw_path}',
                compression = 'gzip',
                columns     = {{'datetime': 'VARCHAR', 'logContent': 'JSON'}}
            )
        """)

        row_count = con.execute("SELECT COUNT(*) FROM raw").fetchone()[0]

        if row_count > 0:
            con.execute(f"""
                COPY raw TO '{parquet_path}'
                (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000)
            """)

        return row_count
    finally:
        con.close()


# ── Handler ───────────────────────────────────────────────────────────────────

def handler(ctx, data: io.BytesIO = None):
    try:
        body = json.loads(data.getvalue())
        logger.info(f"Event: {json.dumps(body)[:400]}")

        namespace, raw_bucket, obj_name = parse_event(body)
        logger.info(f"Source: {namespace}/{raw_bucket}/{obj_name}")

        client     = get_os_client()
        parquet_ns = PARQUET_NAMESPACE or namespace

        with tempfile.TemporaryDirectory() as tmpdir:
            raw_path     = os.path.join(tmpdir, "raw.json.gz")
            parquet_path = os.path.join(tmpdir, "out.parquet")

            # ── Download ──────────────────────────────────────────────────────
            resp = client.get_object(namespace, raw_bucket, obj_name)
            with open(raw_path, "wb") as f:
                for chunk in resp.data.raw.stream(1024 * 1024, decode_content=False):
                    f.write(chunk)

            raw_size = os.path.getsize(raw_path)
            logger.info(f"Downloaded {raw_size:,} bytes")

            # ── Convert ───────────────────────────────────────────────────────
            row_count = convert(raw_path, parquet_path)
            logger.info(f"Converted {row_count} rows")

            if row_count == 0:
                logger.warning("Empty file — skipping upload")
                return _resp(ctx, {"status": "skipped", "reason": "empty_file", "source": obj_name})

            parquet_size = os.path.getsize(parquet_path)
            logger.info(f"Parquet size: {parquet_size:,} bytes "
                        f"({100 * parquet_size // raw_size}% of raw)")

            # ── Upload ────────────────────────────────────────────────────────
            partition    = infer_partition(obj_name, source=LOG_SOURCE)
            out_obj_name = f"{partition}/{uuid.uuid4().hex}.parquet"

            with open(parquet_path, "rb") as f:
                client.put_object(
                    parquet_ns,
                    PARQUET_BUCKET,
                    out_obj_name,
                    f,
                    content_type="application/octet-stream"
                )

            logger.info(f"Uploaded → {PARQUET_BUCKET}/{out_obj_name}")

            return _resp(ctx, {
                "status":         "ok",
                "source_object":  obj_name,
                "parquet_object": out_obj_name,
                "rows":           row_count,
                "raw_bytes":      raw_size,
                "parquet_bytes":  parquet_size,
            })

    except Exception as e:
        logger.exception(f"Handler failed: {e}")
        raise


def _resp(ctx, payload: dict):
    return response.Response(
        ctx,
        response_data=json.dumps(payload),
        headers={"Content-Type": "application/json"}
    )