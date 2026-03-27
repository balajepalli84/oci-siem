-- ============================================================================
-- 1. Last pipeline run time per job
-- ============================================================================
SELECT job_name,
       MAX(run_time)                              AS last_run,
       COUNT(*)                                   AS total_entries,
       SUM(CASE WHEN status = 'SUCCESS'    THEN 1 ELSE 0 END) AS success,
       SUM(CASE WHEN status = 'FAILED'     THEN 1 ELSE 0 END) AS failed,
       SUM(CASE WHEN status = 'LOOP_ERROR' THEN 1 ELSE 0 END) AS loop_errors
FROM   job_run_log
GROUP  BY job_name
ORDER  BY last_run DESC;


-- ============================================================================
-- 2. Last 20 job log entries (most recent activity across all pipelines)
-- ============================================================================
SELECT run_time,
       job_name,
       SUBSTR(NVL(source_name,'–'), 1, 60)  AS source_file,
       status,
       NVL(TO_CHAR(rows_processed),'–')     AS rows,
       SUBSTR(details, 1, 150)              AS details
FROM   job_run_log
ORDER  BY run_time DESC
FETCH  FIRST 20 ROWS ONLY;


-- ============================================================================
-- 3. All distinct error messages from job_run_log with file counts
-- ============================================================================
SELECT SUBSTR(details, 1, 300)    AS error_text,
       COUNT(*)                   AS occurrences,
       MIN(run_time)              AS first_seen,
       MAX(run_time)              AS last_seen
FROM   job_run_log
WHERE  status IN ('FAILED','LOOP_ERROR')
GROUP  BY SUBSTR(details, 1, 300)
ORDER  BY occurrences DESC;


-- ============================================================================
-- 4. Flow file processing health with error details
-- ============================================================================
SELECT processed_flag,
       status,
       COUNT(*)                    AS files,
       MIN(last_modified_ts)       AS oldest_file,
       MAX(last_modified_ts)       AS newest_file,
       MAX(retry_count)            AS max_retries
FROM   flow_new_files
GROUP  BY processed_flag, status
ORDER  BY processed_flag, status;


-- ============================================================================
-- 5. Audit file processing health with error details
-- ============================================================================
SELECT processed_flag,
       status,
       COUNT(*)                    AS files,
       MIN(last_modified_ts)       AS oldest_file,
       MAX(last_modified_ts)       AS newest_file,
       MAX(retry_count)            AS max_retries
FROM   audit_new_files
GROUP  BY processed_flag, status
ORDER  BY processed_flag, status;


-- ============================================================================
-- 6. Files still erroring — most recent 20 with full error message
-- ============================================================================
SELECT 'FLOW'                                      AS pipeline,
       object_name,
       status,
       retry_count,
       last_modified_ts,
       SUBSTR(error_message, 1, 300)               AS error_message
FROM   flow_new_files
WHERE  processed_flag IN ('E','N')
  AND  status NOT IN ('NEW','PROCESSING')
UNION ALL
SELECT 'AUDIT',
       object_name,
       status,
       retry_count,
       last_modified_ts,
       SUBSTR(error_message, 1, 300)
FROM   audit_new_files
WHERE  processed_flag IN ('E','N')
  AND  status NOT IN ('NEW','PROCESSING')
ORDER  BY last_modified_ts DESC
FETCH  FIRST 20 ROWS ONLY;


-- ============================================================================
-- 7. Scheduler job status (is the job running / enabled / last fired)
-- ============================================================================
SELECT job_name,
       enabled,
       state,
       last_start_date,
       last_run_duration,
       next_run_date,
       run_count,
       failure_count
FROM   user_scheduler_jobs
WHERE  job_name IN (
    'AUDIT_PIPELINE_JOB',
    'FLOW_PIPELINE_JOB',
    'CTI_ABUSECH_SYNC_JOB'
)
ORDER  BY job_name;
