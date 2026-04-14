#!/bin/bash
# clean_capture_burst.sh — Start clean capture for N minutes, then stop.
# Cron: 0 * * * * /opt/dfi2/hunter/clean_capture_burst.sh
# Captures real network traffic (watchlist IPs excluded) for ML training data.

set -euo pipefail
SERVICE="dfi-clean-capture"
BURST_SECONDS=${1:-300}  # 5 minutes default, override via arg

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [clean-burst] $*" | tee -a /var/log/clean-burst.log; }

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

# Count captured flows
COUNT=$(clickhouse-client --query="SELECT count() FROM dfi_clean.flows WHERE first_ts > now() - INTERVAL 10 MINUTE" 2>/dev/null || echo "?")
log "DONE: burst complete, recent flows: $COUNT"
