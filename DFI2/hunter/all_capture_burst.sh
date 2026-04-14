#!/bin/bash
# all_capture_burst.sh — Switch to CAPTURE_MODE=all for N seconds, then back to honeypot.
# Cron: 40 * * * * /opt/dfi2/hunter/all_capture_burst.sh 600 >> /var/log/all-burst.log 2>&1
# Captures ALL SPAN traffic (honeypot=attack, everything else=clean baseline).
# Both XGB 5-class + CNN 3-class score every flow during burst.

set -euo pipefail
ENV_FILE="/etc/dfi-hunter/env2"
SERVICE="dfi-hunter2"
BURST_SECONDS=${1:-600}  # 10 minutes default

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [all-burst] $*"; }

# Only run if currently in honeypot mode (avoid stacking if previous burst overran)
CURRENT=$(grep '^CAPTURE_MODE=' "$ENV_FILE" | cut -d= -f2)
if [ "$CURRENT" != "honeypot" ]; then
    log "SKIP: CAPTURE_MODE=$CURRENT (not honeypot), previous burst may still be running"
    exit 0
fi

log "START: switching to CAPTURE_MODE=all for ${BURST_SECONDS}s"
sed -i 's/CAPTURE_MODE=honeypot/CAPTURE_MODE=all/' "$ENV_FILE"
systemctl restart "$SERVICE"

log "CAPTURING: waiting ${BURST_SECONDS}s"
sleep "$BURST_SECONDS"

log "STOP: switching back to CAPTURE_MODE=honeypot"
sed -i 's/CAPTURE_MODE=all/CAPTURE_MODE=honeypot/' "$ENV_FILE"
systemctl restart "$SERVICE"

COUNT=$(clickhouse-client --query="SELECT count() FROM dfi.flows WHERE first_ts > now() - INTERVAL 15 MINUTE" 2>/dev/null || echo "?")
log "DONE: burst complete, recent flows (15min): $COUNT"
