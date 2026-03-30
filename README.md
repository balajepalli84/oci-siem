# OCI Security Lake – CTI Pipeline

> **Autonomous threat detection on Oracle Autonomous Database (ADB)**  
> Ingests OCI Audit Logs and VCN Flow Logs from Object Storage, cross-references every IP address against live threat intelligence from AlienVault OTX, Abuse.ch ThreatFox, and Abuse.ch Feodo Tracker, and writes enriched alerts into queryable ADB tables — all driven by `DBMS_SCHEDULER`.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Database Objects](#database-objects)
  - [Core Tables](#core-tables)
  - [Alert Tables](#alert-tables)
  - [Work-Queue Tables](#work-queue-tables)
  - [Supporting Tables](#supporting-tables)
  - [Indexes](#indexes)
- [Threat Intelligence Ingestion](#threat-intelligence-ingestion)
  - [AlienVault OTX (`cti_otx_pkg`)](#alienvault-otx-cti_otx_pkg)
  - [Abuse.ch ThreatFox (`cti_abusech_pkg.sync_threatfox`)](#abusech-threatfox-cti_abusech_pkgsync_threatfox)
  - [Abuse.ch Feodo Tracker (`cti_abusech_pkg.sync_feodo`)](#abusech-feodo-tracker-cti_abusech_pkgsync_feodo)
- [Audit Log Pipeline](#audit-log-pipeline)
  - [`DISCOVER_AUDIT_FILES`](#discover_audit_files)
  - [`PROCESS_AUDIT_FILE`](#process_audit_file)
  - [`PROCESS_ALL_AUDIT_FILES`](#process_all_audit_files)
  - [`RUN_AUDIT_PIPELINE`](#run_audit_pipeline)
- [VCN Flow Log Pipeline](#vcn-flow-log-pipeline)
  - [`DISCOVER_FLOW_FILES`](#discover_flow_files)
  - [`PROCESS_FLOW_FILE`](#process_flow_file)
  - [`PROCESS_ALL_FLOW_FILES`](#process_all_flow_files)
  - [`RUN_FLOW_PIPELINE`](#run_flow_pipeline)
- [IOC Matching Logic](#ioc-matching-logic)
  - [Severity Classification](#severity-classification)
  - [Deduplication Strategy](#deduplication-strategy)
- [Scheduler Jobs](#scheduler-jobs)
- [Validation Queries](#validation-queries)
- [Key Bug Fixes (v2 — `updated_file.txt`)](#key-bug-fixes-v2)
- [Prerequisites & Deployment](#prerequisites--deployment)
- [Configuration Reference](#configuration-reference)

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────────┐
│  OCI Service Connector Hub                                        │
│  ┌────────────────────┐    ┌──────────────────────────────────┐   │
│  │  OCI Audit Logs    │    │  VCN Flow Logs                   │   │
│  │  (*.log.gz)        │    │  (*.log.gz)                      │   │
│  └────────┬───────────┘    └──────────────┬───────────────────┘   │
│           │ Object Storage                │ Object Storage         │
│    Security_Lake_Audit_Logs         Security_Lake_Flow_Logs        │
└───────────┼─────────────────────────────┼───────────────────────┘
            │                             │
            ▼                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  Oracle Autonomous Database (ADB) – ociateam / us-ashburn-1       │
│                                                                   │
│  ┌──────────────────┐   ┌──────────────────┐                     │
│  │ DISCOVER_AUDIT_  │   │ DISCOVER_FLOW_   │  (every 15/30 min)  │
│  │ FILES            │   │ FILES            │                     │
│  └──────────────────┘   └──────────────────┘                     │
│         │                       │                                 │
│         ▼                       ▼                                 │
│  ┌──────────────┐       ┌──────────────┐                         │
│  │audit_new_    │       │flow_new_     │  ← work queues          │
│  │files         │       │files         │                         │
│  └──────┬───────┘       └──────┬───────┘                         │
│         │                      │                                  │
│         ▼                      ▼                                  │
│  PROCESS_AUDIT_FILE     PROCESS_FLOW_FILE                         │
│  (external table per    (external table per                        │
│   file, IOC MERGE)       file, IOC MERGE)                         │
│         │                      │                                  │
│         ▼                      ▼                                  │
│  ┌──────────────┐       ┌──────────────┐                         │
│  │ audit_alerts │       │ flow_alerts  │  ← alert stores         │
│  └──────────────┘       └──────────────┘                         │
│                                                                   │
│  CTI Sources (daily sync at 02:00 UTC)                            │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐   │
│  │ OTX (pulses) │  │ ThreatFox (ip:   │  │ Feodo (botnet    │   │
│  │ → cti_otx_   │  │ port IOCs)       │  │ C2 blocklist)    │   │
│  │   iocs       │  │ → cti_iocs       │  │ → cti_iocs       │   │
│  └──────────────┘  └──────────────────┘  └──────────────────┘   │
└───────────────────────────────────────────────────────────────────┘
```

All connectivity uses `OCI$RESOURCE_PRINCIPAL` — no long-lived credentials stored in the database.

---

## Database Objects

### Core Tables

#### `cti_otx_iocs`

Stores IPv4 Indicators of Compromise pulled from AlienVault OTX subscription pulses.

| Column | Type | Description |
|--------|------|-------------|
| `indicator_type` | VARCHAR2(30) | Always `'IPv4'` for this pipeline |
| `indicator_value` | VARCHAR2(200) | The IP address |
| `pulse_id` | VARCHAR2(100) | OTX pulse identifier |
| `pulse_name` | VARCHAR2(500) | Human-readable pulse name (used for severity scoring) |
| `description` | VARCHAR2(2000) | Pulse description |
| `threat_score` | NUMBER | Threat score (defaults to 50 for OTX) |
| `first_seen` / `last_seen` | TIMESTAMP | Temporal bounds of the IOC |
| `is_active` | CHAR(1) | `'Y'` = active, `'N'` = inactive |
| `source_name` | VARCHAR2(50) | Always `'OTX'` |
| `raw_json` | CLOB | Full raw JSON payload from the OTX API |
| `created_at` / `updated_at` | TIMESTAMP | Audit timestamps |

Unique index on `(indicator_type, indicator_value, pulse_id)` prevents duplicate pulse-indicator pairs.

---

#### `cti_iocs`

Multi-source IOC table — the canonical store for Abuse.ch feeds (ThreatFox + Feodo) and any future CTI integrations.

| Column | Type | Description |
|--------|------|-------------|
| `ioc_id` | NUMBER (identity PK) | Surrogate key |
| `indicator_type` | VARCHAR2(30) | `'IPv4'` |
| `indicator_value` | VARCHAR2(200) | IP address (stripped from `ip:port` format for ThreatFox) |
| `source_name` | VARCHAR2(100) | `'ABUSECH_THREATFOX'` or `'ABUSECH_FEODO'` |
| `source_key` | VARCHAR2(300) | Unique key per source: `THREATFOX-<id>` or `FEODO-<ip>-<port>` |
| `pulse_id` / `pulse_name` | VARCHAR2 | Maps to ThreatFox IOC ID / Feodo malware family |
| `description` | VARCHAR2(4000) | Enriched description including port, AS name, country |
| `threat_score` | NUMBER | Confidence level from ThreatFox; fixed `85` for Feodo (high-confidence C2) |
| `first_seen` / `last_seen` | TIMESTAMP | IOC temporal bounds |
| `is_active` | CHAR(1) | `'Y'` for ThreatFox results; `'Y'`/`'N'` for Feodo based on `status` field |
| `raw_json` | CLOB (CHECK IS JSON) | Full structured payload |

Unique index on `(source_name, source_key)` to support idempotent MERGE upserts. Secondary index on `(indicator_value, indicator_type, is_active)` for fast IOC lookup during alert generation.

---

#### `cti_config`

Key-value configuration store.

| `config_key` | Purpose |
|---|---|
| `OTX_API_KEY` | AlienVault OTX API key |
| `OTX_BASE_URL` | `https://otx.alienvault.com/api/v1` |
| `OTX_LAST_SYNC_UTC` | Epoch marker for incremental OTX sync |
| `ABUSECH_THREATFOX_URL` | `https://threatfox-api.abuse.ch/api/v1/` |
| `ABUSECH_FEODO_URL` | `https://feodotracker.abuse.ch/downloads/ipblocklist.json` |
| `THREATFOX_AUTH_KEY` | ThreatFox API authentication key |
| `THREATFOX_DAYS` | Lookback window for ThreatFox query (1–7 days) |

---

### Alert Tables

#### `audit_alerts`

One row per unique (audit log file × source IP × API event × IOC pulse). Populated by `PROCESS_AUDIT_FILE`.

| Column | Description |
|--------|-------------|
| `alert_id` | Identity PK |
| `alert_time` | `SYSTIMESTAMP` at processing time |
| `event_time` | Timestamp parsed from `$.datetime` in the log JSON |
| `source_ip` | Caller IP from `$.data.identity.ipAddress` |
| `principal_name` | OCI principal from `$.data.identity.principalName` |
| `event_name` | API action from `$.data.eventName` (e.g., `GetObject`) |
| `compartment_id` / `compartment_name` | OCI compartment context |
| `response_status` | HTTP response code from `$.data.response.status` |
| `object_name` | Request path from `$.data.request.path` |
| `indicator_value` / `indicator_type` | Matched IOC |
| `pulse_id` / `pulse_name` | Source threat pulse |
| `severity` | `HIGH` / `MEDIUM` / `LOW` (keyword-derived) |
| `match_reason` | Human-readable match description |
| `raw_event` | Full raw JSON log line (CLOB) |

---

#### `flow_alerts`

One row per unique (flow log file × src IP × dst IP × IOC pulse). Populated by `PROCESS_FLOW_FILE`.

| Column | Description |
|--------|-------------|
| `src_ip` / `dst_ip` | Source and destination addresses |
| `src_port` / `dst_port` | Transport-layer ports |
| `protocol` | TCP/UDP/ICMP etc. |
| `action` | `ACCEPT` or `REJECT` |
| `vnic_ocid` | VNIC involved in the flow |
| `subnet_id` | Subnet of the observed flow |
| `compartment_id` | OCI compartment context |
| `log_status` | Flow log status field |
| `match_reason` | `'Matched source IP...'` or `'Matched destination IP...'` |

Unlike audit alerts, flow alerts check **both** source and destination IPs against IOCs in a single `MERGE` statement using `UNION ALL`, so an alert is generated for each direction that matches.

---

### Work-Queue Tables

#### `audit_new_files` / `flow_new_files`

Track every Object Storage file seen by the discovery procedures. Act as the pipeline's durable work queue with retry logic.

| Column | Description |
|--------|-------------|
| `object_name` (PK) | Object Storage key (e.g., `20260324T021117Z_...0.log.gz`) |
| `bytes` / `checksum` | File metadata from `DBMS_CLOUD.LIST_OBJECTS` |
| `created_ts` / `last_modified_ts` | File timestamps |
| `processed_flag` | `'N'` = new, `'Y'` = done, `'E'` = error |
| `status` | `NEW` → `PROCESSING` → `PROCESSED` / `ERROR` / `FAILED_MAX_RETRY` |
| `retry_count` | Incremented on each failure; capped at 3 before abandonment |
| `error_message` | Last exception message (VARCHAR2 4000) |

---

### Supporting Tables

#### `job_run_log`

Audit log for every pipeline execution. Extended in v2 to support CTI sync jobs.

| Column | Description |
|--------|-------------|
| `job_name` | `AUDIT_PIPELINE`, `FLOW_PIPELINE`, `CTI_SYNC`, etc. |
| `source_name` | Object name or CTI source being processed |
| `status` | `SUCCESS`, `FAILED`, `LOOP_ERROR` |
| `rows_processed` | Number of alerts merged or IOCs upserted |
| `run_time` | `SYSTIMESTAMP` |
| `details` | Free-text details or truncated error message |

---

### Indexes

| Index | Table | Columns | Purpose |
|-------|-------|---------|---------|
| `cti_otx_iocs_u1` | `cti_otx_iocs` | `(indicator_type, indicator_value, pulse_id)` | Prevent duplicate OTX IOCs |
| `cti_iocs_u1` | `cti_iocs` | `(source_name, source_key)` | Idempotent MERGE for Abuse.ch |
| `cti_iocs_n1` | `cti_iocs` | `(indicator_value, indicator_type, is_active)` | Fast IOC lookup at alert time |
| `audit_alerts_u1` | `audit_alerts` | `(object_name, source_ip, event_name, pulse_id)` | Prevent duplicate audit alerts |
| `flow_alerts_u1` | `flow_alerts` | `(object_name, src_ip, dst_ip, NVL(pulse_id,'NO_PULSE'))` | Prevent duplicate flow alerts |

---

## Threat Intelligence Ingestion

All CTI sync procedures use `DBMS_CLOUD.SEND_REQUEST` (or `UTL_HTTP` in earlier iterations) and upsert via `MERGE` — making every run idempotent.

### AlienVault OTX (`cti_otx_pkg`)

**Package**: `cti_otx_pkg`  
**Procedure**: `sync_ipv4_iocs`  
**Target table**: `cti_otx_iocs`

**What it does:**

1. Reads `OTX_API_KEY` and `OTX_BASE_URL` from `cti_config`.
2. Calls `GET /pulses/subscribed?limit=20&page=1` with the `X-OTX-API-KEY` header.
3. Parses the response JSON using `JSON_TABLE` with a **nested path** — it simultaneously unnests pulse-level fields (`$.results[*]`) and their nested indicators (`$.indicators[*]`), joining them in a single SQL pass.
4. Filters for `indicator_type = 'IPv4'` only.
5. Inserts new IOCs (skips existing ones via `NOT EXISTS` in v1; upgraded to `MERGE` upsert in v2).
6. Logs success/failure to `job_run_log`.

**Key JSON paths extracted:**
- `$.results[*].id` → `pulse_id`
- `$.results[*].name` → `pulse_name`
- `$.results[*].description` → `description`
- `$.results[*].indicators[*].type` → `indicator_type`
- `$.results[*].indicators[*].indicator` → `indicator_value`

**Validation:**
```sql
SELECT source_name, indicator_type, COUNT(*) FROM cti_otx_iocs
GROUP BY source_name, indicator_type;
```

---

### Abuse.ch ThreatFox (`cti_abusech_pkg.sync_threatfox`)

**Package**: `cti_abusech_pkg`  
**Procedure**: `sync_threatfox`  
**Target table**: `cti_iocs`

**What it does:**

1. Reads `ABUSECH_THREATFOX_URL`, `THREATFOX_AUTH_KEY`, and `THREATFOX_DAYS` from `cti_config`. Validates that `THREATFOX_DAYS` is between 1 and 7.
2. POSTs `{"query":"get_iocs","days":<N>}` to the ThreatFox API with `Auth-Key` header.
3. Checks `$.query_status` — exits cleanly if `'no_results'`, raises if anything other than `'ok'`.
4. Parses `$.data[*]` with `JSON_TABLE`, extracting:
   - `$.id` → `ioc_id` → used as `pulse_id` and part of `source_key` (`THREATFOX-<id>`)
   - `$.ioc` → raw IOC value in `ip:port` format → the IP portion is extracted via `SUBSTR(..., INSTR(...,':') - 1)`
   - `$.ioc_type` = `'ip:port'` filter ensures only network IOCs are processed
   - `$.malware_printable` → `pulse_name`
   - `$.threat_type_desc` → `description`
   - `$.confidence_level` → `threat_score`
   - `$.first_seen` / `$.last_seen` → timestamp strings cleaned of `' UTC'` suffix before conversion
5. IPv4 format validated with `REGEXP_LIKE(ip, '^[0-9]{1,3}(\.[0-9]{1,3}){3}$')`.
6. Upserted into `cti_iocs` via `MERGE` on `(source_name, source_key)`.

---

### Abuse.ch Feodo Tracker (`cti_abusech_pkg.sync_feodo`)

**Package**: `cti_abusech_pkg`  
**Procedure**: `sync_feodo`  
**Target table**: `cti_iocs`

**What it does:**

1. Fetches `ABUSECH_FEODO_URL` — a JSON array (`$[*]`) of known botnet C2 servers.
2. Parses each entry with `JSON_TABLE`:
   - `$.ip_address` → `indicator_value`
   - `$.port` → used in `source_key` (`FEODO-<ip>-<port>`) and in the description
   - `$.status` → if `'online'`, `is_active = 'Y'`; otherwise `'N'` — Feodo is the only source that can mark IOCs inactive
   - `$.malware` → `pulse_name` (defaults to `'Feodo'` if null)
   - `$.as_name` / `$.country` → embedded in the description string
   - `$.first_seen` / `$.last_online` → timestamps
3. Assigns a fixed `threat_score` of **85** (high confidence — these are confirmed C2 infrastructure).
4. Upserted into `cti_iocs` via `MERGE` on `(source_name, source_key)`.

**`sync_all` orchestrator** calls `sync_threatfox` then `sync_feodo` in sequence. This is what the scheduler job calls.

---

## Audit Log Pipeline

OCI Audit Logs arrive in `Security_Lake_Audit_Logs` Object Storage bucket via Service Connector Hub, compressed as gzip newline-delimited JSON files.

### `DISCOVER_AUDIT_FILES`

**What it does:**

Calls `DBMS_CLOUD.LIST_OBJECTS` against the bucket URI and inserts any `.log.gz` files not already tracked in `AUDIT_NEW_FILES`. Uses `OCI$RESOURCE_PRINCIPAL` — no credential required at the DB level.

The `NOT EXISTS` subquery is joined against the aliased result of `LIST_OBJECTS` using the `l.` prefix — this was the critical fix in v2 (the original had an unqualified `object_name` that resolved to the inner table, causing all files to appear as already-existing).

Files are inserted with `processed_flag = 'N'`, `status = 'NEW'`, `retry_count = 0`.

---

### `PROCESS_AUDIT_FILE`

**Input**: `p_object_name` — the Object Storage key (filename portion only, not the full URI).

**What it does step by step:**

1. **Mark in-progress**: `UPDATE AUDIT_NEW_FILES SET STATUS = 'PROCESSING'` — prevents concurrent re-processing.
2. **Drop/recreate external table**: `AUDIT_LOG_ONE_EXT` is a temporary external table pointing at a single gzip log file. It uses `DBMS_CLOUD.CREATE_EXTERNAL_TABLE` with:
   - `delimiter = 0x01` (SOH byte — OCI log format separator)
   - `recorddelimiter = \n`
   - `compression = gzip`
   - Single column: `raw_line VARCHAR2(32767)` — each row is one raw JSON event
3. **IOC MERGE**: Executes a dynamic `MERGE INTO AUDIT_ALERTS` using `EXECUTE IMMEDIATE`. The source subquery:
   - Reads every `raw_line` from `AUDIT_LOG_ONE_EXT`
   - Extracts `$.data.identity.ipAddress` as `source_ip`
   - JOINs against a `UNION` of active IPv4 IOCs from **both** `CTI_OTX_IOCS` and `CTI_IOCS` — ensuring all three threat sources are checked
   - Extracts event metadata: `event_name`, `principal_name`, `compartment_id/name`, `response_status`, `object_name` (request path)
   - Applies severity classification (see [IOC Matching Logic](#ioc-matching-logic))
   - Rows with a null `source_ip` are filtered out before the join
4. **Mark complete**: Updates `processed_flag = 'Y'`, `status = 'PROCESSED'`.
5. **Log**: Inserts a `job_run_log` record with row count.
6. **Cleanup**: Drops `AUDIT_LOG_ONE_EXT` — keeps the schema clean between files.

**On error**: Catches `OTHERS`, drops the external table, increments `retry_count`, sets `status = 'ERROR'` or `'FAILED_MAX_RETRY'` (if retry_count ≥ 3), logs to `job_run_log`, and re-raises so the outer loop can capture it.

---

### `PROCESS_ALL_AUDIT_FILES`

Iterates `AUDIT_NEW_FILES` for rows where:
- `processed_flag = 'N'` (never attempted), OR
- `processed_flag = 'E'` AND `retry_count < 3` (failed but still retryable)

Ordered by `LAST_MODIFIED_TS` (oldest first). Each file processed in its own `BEGIN/EXCEPTION` block — a single file failure does not abort the batch. Loop-level errors are logged to `job_run_log` with `LOOP_ERROR` status.

---

### `RUN_AUDIT_PIPELINE`

Top-level orchestrator — simply calls `DISCOVER_AUDIT_FILES` then `PROCESS_ALL_AUDIT_FILES`. This is what `AUDIT_PIPELINE_JOB` invokes.

---

## VCN Flow Log Pipeline

Structurally identical to the audit pipeline but operating on `Security_Lake_Flow_Logs` and populating `FLOW_ALERTS`. The key difference is the **dual-direction IOC matching**.

### `DISCOVER_FLOW_FILES`

Same pattern as `DISCOVER_AUDIT_FILES` — lists `Security_Lake_Flow_Logs` bucket, inserts new `.log.gz` entries into `FLOW_NEW_FILES`.

---

### `PROCESS_FLOW_FILE`

**Input**: `p_object_name`

Follows the same mark → create external table → MERGE → mark done → cleanup lifecycle as the audit procedure, with these differences:

**External table**: `FLOW_LOG_ONE_EXT` pointing at the flow log file.

**IOC MERGE — dual-direction matching**: The `MERGE INTO FLOW_ALERTS` source subquery is a `UNION ALL` of two branches:

**Branch 1 — Source IP match**:
- Joins `FLOW_LOG_ONE_EXT` to the IOC UNION on `$.data.sourceAddress`
- `match_reason = 'Matched source IP from flow log to IOC'`

**Branch 2 — Destination IP match**:
- Joins `FLOW_LOG_ONE_EXT` to the IOC UNION on `$.data.destinationAddress`
- `match_reason = 'Matched destination IP from flow log to IOC'`

Both branches extract the same set of flow fields: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `action`, `vnic_ocid`, `subnet_id`, `compartment_id`, `log_status`.

The bind variable `:1` is used **twice** (once per branch) — both bound to `p_object_name` via `USING p_object_name, p_object_name`.

The `MERGE ON` clause deduplicates on `(object_name, src_ip, dst_ip, pulse_id)` using `NVL(..., 'NO_PULSE')` to handle null pulse IDs safely.

---

### `PROCESS_ALL_FLOW_FILES`

Same as the audit version — loops over unprocessed/retryable flow files, one file per exception-isolated call.

---

### `RUN_FLOW_PIPELINE`

Calls `DISCOVER_FLOW_FILES` then `PROCESS_ALL_FLOW_FILES`. Invoked by `FLOW_PIPELINE_JOB`.

---

## IOC Matching Logic

### IOC Source Union

Both alert pipelines join against a combined IOC view at query time:

```sql
SELECT indicator_type, indicator_value, pulse_id, pulse_name
FROM   CTI_OTX_IOCS
WHERE  is_active = 'Y' AND indicator_type = 'IPv4'
UNION
SELECT indicator_type, indicator_value, pulse_id, pulse_name
FROM   CTI_IOCS
WHERE  is_active = 'Y' AND indicator_type = 'IPv4'
```

`UNION` (not `UNION ALL`) is intentional — if the same IP appears in both OTX and Abuse.ch, it is matched once, preventing duplicate alerts from cross-source overlap.

### Severity Classification

Applied at alert-generation time via a `CASE` expression on the IOC's `pulse_name`:

| Keyword in `pulse_name` | Severity |
|------------------------|----------|
| `MALWARE` | HIGH |
| `BOTNET` | HIGH |
| `C2` | HIGH |
| `SCANNER` | MEDIUM |
| `BRUTE` | MEDIUM |
| _(anything else)_ | LOW |

The match is case-insensitive (`UPPER(NVL(pulse_name,' '))`) and uses `LIKE '%KEYWORD%'` — partial matches qualify.

### Deduplication Strategy

**Audit alerts** deduplicated on: `(object_name, source_ip, event_name, pulse_id)` — same API call from the same IP matched by the same pulse, in the same log file, produces one alert.

**Flow alerts** deduplicated on: `(object_name, src_ip, dst_ip, NVL(pulse_id,'NO_PULSE'))` — same flow pair matched by the same pulse in the same log file produces one alert. The `NVL` guard handles rows with no pulse ID without breaking the unique index.

`MERGE ... WHEN NOT MATCHED THEN INSERT` is used in both cases — no `INSERT` that could raise `ORA-00001`, and no need for a pre-check.

---

## Scheduler Jobs

| Job Name | Procedure | Schedule | Description |
|----------|-----------|----------|-------------|
| `AUDIT_PIPELINE_JOB` | `RUN_AUDIT_PIPELINE` | Every 15 minutes | Discover and process new OCI Audit Log files |
| `FLOW_PIPELINE_JOB` | `RUN_FLOW_PIPELINE` | Every 30 minutes | Discover and process new VCN Flow Log files |
| `CTI_ABUSECH_SYNC_JOB` | `CTI_ABUSECH_PKG.SYNC_ALL` | Daily at 02:00 UTC | Pull latest ThreatFox and Feodo IOCs into `cti_iocs` |

OTX sync (`cti_otx_pkg.sync_ipv4_iocs`) should be scheduled separately as a `STORED_PROCEDURE` job if incremental sync is desired. The Abuse.ch job is the only one created automatically by the v2 script.

All jobs use `DBMS_SCHEDULER.DROP_JOB(..., force => TRUE)` before recreating — safe for repeated script runs.

---

## Validation Queries

Run these manually after deployment to confirm the pipeline is healthy.

### File Processing Health

```sql
SELECT 'AUDIT' AS pipeline,
       COUNT(*)                                                  AS total,
       SUM(CASE WHEN processed_flag = 'Y' THEN 1 ELSE 0 END)   AS processed,
       SUM(CASE WHEN processed_flag = 'E' THEN 1 ELSE 0 END)   AS errored,
       SUM(CASE WHEN processed_flag = 'N' THEN 1 ELSE 0 END)   AS pending,
       SUM(CASE WHEN processed_flag = 'E'
                 AND NVL(retry_count,0) >= 3 THEN 1 ELSE 0 END) AS max_retry_hit
FROM   audit_new_files
UNION ALL
SELECT 'FLOW', COUNT(*),
       SUM(CASE WHEN processed_flag = 'Y' THEN 1 ELSE 0 END),
       SUM(CASE WHEN processed_flag = 'E' THEN 1 ELSE 0 END),
       SUM(CASE WHEN processed_flag = 'N' THEN 1 ELSE 0 END),
       SUM(CASE WHEN processed_flag = 'E'
                 AND NVL(retry_count,0) >= 3 THEN 1 ELSE 0 END)
FROM   flow_new_files;
```

### IOC Coverage by Source

```sql
SELECT source_name,
       indicator_type,
       COUNT(*)                                           AS total_iocs,
       SUM(CASE WHEN is_active = 'Y' THEN 1 ELSE 0 END) AS active_iocs
FROM (
    SELECT source_name, indicator_type, is_active FROM cti_otx_iocs
    UNION ALL
    SELECT source_name, indicator_type, is_active FROM cti_iocs
)
GROUP BY source_name, indicator_type
ORDER BY source_name;
```

### Alert Summary — Audit

```sql
SELECT severity,
       COUNT(*)                  AS total_alerts,
       COUNT(DISTINCT source_ip) AS distinct_ips,
       MAX(alert_time)           AS latest_alert
FROM   audit_alerts
GROUP  BY severity
ORDER  BY CASE severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END;
```

### Alert Summary — Flow

```sql
SELECT severity,
       COUNT(*)                  AS total_alerts,
       COUNT(DISTINCT src_ip)    AS distinct_src_ips,
       COUNT(DISTINCT dst_ip)    AS distinct_dst_ips,
       MAX(alert_time)           AS latest_alert
FROM   flow_alerts
GROUP  BY severity
ORDER  BY CASE severity WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END;
```

### Recent Job Activity

```sql
SELECT job_name,
       NVL(source_name, '–')            AS source,
       status,
       NVL(TO_CHAR(rows_processed),'–') AS rows,
       run_time,
       SUBSTR(details, 1, 100)          AS details
FROM   job_run_log
ORDER  BY run_time DESC
FETCH  FIRST 30 ROWS ONLY;
```

### Files Stuck in ERROR

```sql
SELECT object_name, retry_count, status, error_message
FROM   audit_new_files
WHERE  processed_flag = 'E'
ORDER  BY retry_count DESC;
```

---

## Key Bug Fixes (v2)

The `updated_file.txt` script is the fixed, production-ready version. `queries.txt` represents the earlier iterative development. The following critical issues were resolved:

| # | Bug | Impact | Fix |
|---|-----|--------|-----|
| 1 | `DISCOVER_*`: unqualified `object_name` in `NOT EXISTS` resolved to the inner `AUDIT_NEW_FILES` table instead of the `LIST_OBJECTS` result | All files appeared as already-discovered; discovery was a no-op | Aliased the `LIST_OBJECTS` TVF result as `l`, referenced `l.object_name` |
| 2 | `audit_alerts_u1` index referenced `source_file` (non-existent column) | Index creation failed; `ORA-01418` on every run | Dropped and recreated index on `object_name` (correct column name) |
| 3 | IOC matching joined only `CTI_OTX_IOCS` | Abuse.ch IOCs from `CTI_IOCS` were never matched against logs | Changed JOIN to a `UNION` subquery combining both tables |
| 4 | Alert inserts used `INSERT` — no duplicate guard | `ORA-00001` on any re-processed file or retry | Replaced with `MERGE ... WHEN NOT MATCHED THEN INSERT` |
| 5 | No `retry_count` column on work-queue tables | Could not track or cap retry attempts | Added `retry_count NUMBER DEFAULT 0` via safe `ALTER TABLE` |
| 6 | `PROCESS_FLOW_FILE` missing `STATUS = 'PROCESSING'` update | Files could be picked up concurrently; no in-progress visibility | Added `UPDATE FLOW_NEW_FILES SET STATUS = 'PROCESSING'` at procedure start |
| 7 | `PROCESS_ALL_*` exception handler used `NULL` (swallowed silently) | Loop errors left no trace | Changed to log to `job_run_log` with `LOOP_ERROR` status before continuing |
| 8 | `cti_abusech_pkg` package SPEC was missing | Package body could not be compiled | Added full package SPEC with `sync_threatfox`, `sync_feodo`, `sync_all` signatures |
| 9 | Abuse.ch URLs missing from `cti_config` | `get_config()` would raise `NO_DATA_FOUND` at runtime | Added `MERGE` insert for `ABUSECH_THREATFOX_URL` and `ABUSECH_FEODO_URL` |
| 10 | `CTI_ABUSECH_SYNC_JOB` was never created | Feodo/ThreatFox sync only ran on-demand | Added scheduled job (daily 02:00 UTC) in Section 7 |

---

## Prerequisites & Deployment

### ADB Requirements

- Oracle Autonomous Database (Shared or Dedicated) — 19c or later
- `OCI$RESOURCE_PRINCIPAL` credential configured and the ADB's dynamic group granted read access to both Object Storage buckets
- `DBMS_CLOUD` package available (standard on ADB)

### Deployment Order

```
1. queries.txt      → Run DDL sections only (CREATE TABLE / INDEX statements)
                      to establish the schema for the first time.

2. updated_file.txt → Run the full script to apply DDL fixes, populate config,
                      create/replace all procedures and packages, and register
                      the scheduler jobs.
```

> If deploying to a fresh schema, run both files in order. If upgrading an existing deployment, run only `updated_file.txt` — the `ALTER TABLE ... ADD` statements are wrapped in `BEGIN/EXCEPTION` blocks that silently skip `ORA-01430` (column already exists).

### Credentials Setup

```sql
-- Update your actual keys
UPDATE cti_config SET config_value = '<YOUR_OTX_KEY>'         WHERE config_key = 'OTX_API_KEY';
UPDATE cti_config SET config_value = '<YOUR_THREATFOX_KEY>'   WHERE config_key = 'THREATFOX_AUTH_KEY';
UPDATE cti_config SET config_value = '7'                      WHERE config_key = 'THREATFOX_DAYS';
COMMIT;
```

### Initial CTI Load

```sql
-- Seed OTX IOCs
BEGIN cti_otx_pkg.sync_ipv4_iocs; END;
/

-- Seed Abuse.ch IOCs (ThreatFox + Feodo)
BEGIN cti_abusech_pkg.sync_all; END;
/

-- Seed OTX IOCs
BEGIN cti_otx_pkg.sync_ipv4_iocs; END;
/

-- Trigger pipelines immediately
BEGIN RUN_AUDIT_PIPELINE; END;
/
BEGIN RUN_FLOW_PIPELINE; END;
/
```

---

## Configuration Reference

| Key | Default / Example | Notes |
|-----|--------------------|-------|
| `OTX_API_KEY` | `PUT_YOUR_OTX_KEY_HERE` | From AlienVault OTX profile |
| `OTX_BASE_URL` | `https://otx.alienvault.com/api/v1` | Stable; no change expected |
| `OTX_LAST_SYNC_UTC` | `1970-01-01T00:00:00+00:00` | Reset to epoch for full re-sync |
| `ABUSECH_THREATFOX_URL` | `https://threatfox-api.abuse.ch/api/v1/` | Abuse.ch v1 API |
| `ABUSECH_FEODO_URL` | `https://feodotracker.abuse.ch/downloads/ipblocklist.json` | JSON blocklist |
| `THREATFOX_AUTH_KEY` | `PASTE_YOUR_AUTH_KEY_HERE` | From Abuse.ch account |
| `THREATFOX_DAYS` | `7` | Max 7; governs IOC lookback window |

---

*Tenancy: `ociateam` · Region: `us-ashburn-1` · Credential: `OCI$RESOURCE_PRINCIPAL`*
