#!/bin/bash
# norm_capture_burst.sh — Switch to CAPTURE_MODE=all for 5 min, then back to honeypot.
# Deployed via cron: 0 * * * * /opt/dfi2/hunter/norm_capture_burst.sh
# Gives time-of-day diversity for NORM (label=5) training data.

set -euo pipefail
ENV_FILE="/etc/dfi-hunter/env2"
SERVICE="dfi-hunter2"
BURST_SECONDS=300  # 5 minutes

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [norm-burst] $*" | tee -a /var/log/norm-burst.log; }

# Only run if currently in honeypot mode (avoid stacking if previous burst overran)
CURRENT=$(grep '^CAPTURE_MODE=' "$ENV_FILE" | cut -d= -f2)
if [ "$CURRENT" != "honeypot" ]; then
    log "SKIP: CAPTURE_MODE=$CURRENT (not honeypot), previous burst may still be running"
    exit 0
fi

log "START: switching to CAPTURE_MODE=all"
sed -i 's/CAPTURE_MODE=honeypot/CAPTURE_MODE=all/' "$ENV_FILE"
systemctl restart "$SERVICE"

log "CAPTURING: waiting ${BURST_SECONDS}s"
sleep "$BURST_SECONDS"

log "STOP: switching back to CAPTURE_MODE=honeypot"
sed -i 's/CAPTURE_MODE=all/CAPTURE_MODE=honeypot/' "$ENV_FILE"
systemctl restart "$SERVICE"

log "DONE: burst complete"
