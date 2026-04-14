#!/bin/bash
# dirty_capture_burst.sh — Start dirty capture for N seconds, then stop.
# Captures watchlist IP traffic at D2 depth for ML training data.

set -euo pipefail
SERVICE="dfi-dirty-capture"
BURST_SECONDS=${1:-300}  # 5 minutes default

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [dirty-burst] $*" | tee -a /var/log/dirty-burst.log; }

# Skip if already running
if systemctl is-active --quiet "$SERVICE"; then
    log "SKIP: $SERVICE already running"
    exit 0
fi

log "START: launching $SERVICE for ${BURST_SECONDS}s"
systemctl start "$SERVICE"

sleep "$BURST_SECONDS"

log "STOP: stopping $SERVICE"
systemctl stop "$SERVICE"

COUNT=$(clickhouse-client --query="SELECT count() FROM dfi_dirty.flows WHERE first_ts > now() - INTERVAL 10 MINUTE" 2>/dev/null || echo "?")
log "DONE: burst complete, recent flows: $COUNT"
