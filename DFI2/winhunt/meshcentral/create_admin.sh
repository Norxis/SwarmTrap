#!/usr/bin/env bash
set -euo pipefail
if [[ -z "${MESH_ADMIN_PASS:-}" ]]; then
  read -rsp "Enter MeshCentral admin password: " MESH_ADMIN_PASS
  echo
fi
pct exec 112 -- bash -lc "cd /opt/meshcentral && node node_modules/meshcentral --createaccount admin --pass \"$MESH_ADMIN_PASS\" --domain \"\""
