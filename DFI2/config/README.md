# DFI2 Configuration Files

ClickHouse server configuration snippets deployed to manage system log retention.

## Files

### `system_logs_ttl.xml`

ClickHouse server configuration that sets TTL (time-to-live) auto-delete policies on system log tables. This prevents system logs from growing unbounded and consuming disk space.

**High-volume logs (3-day TTL):**
- `text_log` -- general server text log
- `trace_log` -- query execution traces
- `processors_profile_log` -- query processor profiling
- `asynchronous_metric_log` -- async metric samples

**Standard logs (7-day TTL):**
- `query_log` -- query execution log
- `query_views_log` -- materialized view refresh log
- `part_log` -- data part merge/mutation log
- `metric_log` -- periodic metric snapshots
- `asynchronous_insert_log` -- async insert tracking
- `query_metric_log` -- per-query metric breakdowns
- `background_schedule_pool_log` -- background task scheduling
- `error_log` -- server error log

**Deployment:** Copy to the ClickHouse server config directory (typically `/etc/clickhouse-server/config.d/`) and restart the server. The TTL expressions use `event_date + INTERVAL N DAY DELETE` syntax, which ClickHouse evaluates automatically during merge operations.
