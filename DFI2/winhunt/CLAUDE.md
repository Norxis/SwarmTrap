# WinHunt — Claude Code Instructions

## Connection Priority: API FIRST, MeshCentral FALLBACK

**Priority 1 — REST API** `http://172.16.3.160:9200/api/` — always try this first, fastest.

### EXACT API PATTERN — use this verbatim:
```python
import requests

base = 'http://172.16.3.160:9200/api'

# Submit command
r = requests.post(f'{base}/command', json={
    'command': 'exec',
    'args': {'command': 'PS_COMMAND_HERE', 'timeout': 120}
}, timeout=15)
cmd_id = r.json()['command_id']   # KEY: 'command_id' not 'id'

# Poll — pass ?timeout=120 to server, HTTP client timeout = server timeout + 10
r2 = requests.get(f'{base}/command/{cmd_id}?timeout=120', timeout=130)
result = r2.json().get('result', {})
print(result.get('stdout', ''))   # KEY: nested under 'result', not top-level
print(result.get('returncode'))
```

### PowerShell command rules (exec handler uses `powershell.exe -Command`):
- Use `;` to chain commands — **NEVER `&&`** (cmd.exe syntax, fails in PS)
- Use `;` not newlines: `Set-Location 'C:\path'; & 'python.exe' args`
- Call operator `&` required before executables with spaces in path
- Python path on Windows: `C:\Program Files\Python312\python.exe`
- Set working dir with `Set-Location` before running Python modules

### Export old dataset example (proven working):
```python
ps_cmd = "Set-Location 'C:\\Program Files\\DFI\\agent'; & 'C:\\Program Files\\Python312\\python.exe' -m dfi_agent.export export --format both --buffer 'C:\\Program Files\\DFI\\data\\agent_buffer_restored.db' --output-dir 'C:\\Program Files\\DFI\\data\\old_export'"
r = requests.post(f'{base}/command', json={'command': 'exec', 'args': {'command': ps_cmd, 'timeout': 180}}, timeout=15)
cmd_id = r.json()['command_id']
result = requests.get(f'{base}/command/{cmd_id}?timeout=120', timeout=130).json()
```

**Priority 2 — MeshCentral** — only when REST API is unreachable/failing:
```python
from skills.mesh import MeshSession
with MeshSession() as m:
    m.ps('Get-Service WinHuntAgent')        # single command
    m.ps_file(big_script)                    # multi-line PS1 via file transfer
    m.upload_text(path, content)             # write text file to Windows
    m.upload_bin(local, remote)              # upload binary via CT112 HTTP
    m.svc_restart('WinHuntAgent')            # restart NSSM service
```

**Priority 3 — WinRM** — **DO NOT USE. Broken on Server 2025.** pywinrm fails all transports (ntlm/basic/negotiate). Never attempt WinRM.

### CLI shortcuts (use API where possible):
```bash
python3 skills/health.py                     # health check (uses API + MeshCentral)
python3 skills/status.py                     # full status
python3 skills/logs.py [-n N] [--stderr] [-f] # view logs
python3 skills/svc.py [restart|stop|start]   # manage services
python3 skills/staging.py [--clean|--sample] # staging NDJSON files
python3 skills/redeploy.py                   # redeploy agent code + config
python3 skills/run.py 'PS command'           # run PS via MeshCentral (fallback)
```

### Key technical details:
- **REST API endpoints:** `GET /api/health`, `GET /api/flows`, `GET /api/events`, `POST /api/command`, `GET /api/command/<id>`
- MeshCentral routes: **Paramiko → PV1 → pct exec 112 → meshctrl.js --reply → Windows**
- Multi-line PS with single quotes: use `m.ps_file()` instead of `m.ps()`
- Write bash scripts to CT112 `/tmp/_mc.sh` to avoid escaping issues — never inline meshctrl in bash -c
- **Windows paths: ALWAYS use raw strings, NEVER `\\`** — `r"C:\TEMP\file.zip"` not `"C:\\TEMP\\file.zip"`. The `\\` causes `\n`, `\t`, `\r` to become escape sequences through Python/bash layers. For f-strings needing interpolation, use raw string + `.replace("__VAR__", value)`.

## HARD RULES — Never Violate

1. **nssm restart ONLY via MeshCentral** — NEVER via `POST /api/command`. Running restart/stop inside the agent kills it (exit 0), NSSM treats as intentional stop, does NOT restart. Use `MeshSession.ps('nssm restart WinHuntAgent')`.

2. **NEVER write config files with Set-Content / Out-File** — PowerShell writes UTF-8 BOM → `JSONDecodeError: Unexpected UTF-8 BOM` crash loop. ALWAYS use:
   ```powershell
   [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding $false))
   ```

3. **WinRM is broken on Server 2025** — do not attempt, do not enable, do not spend time on it.

4. **Windows paths: ALWAYS raw strings** — `r"C:\TEMP\file"` never `"C:\\TEMP\\file"`.

## Agent Details

- **Target:** 172.16.3.160 (Windows Server 2025, single NIC)
- **Agent code:** `dfi_agent/` → deployed to `C:\Program Files\DFI\agent\dfi_agent\`
- **Config:** `C:\DFI\config.json` (vm_id=WINHUNT-SRV25)
- **Capture:** Native raw sockets (SIO_RCVALL) — NO Npcap/pcapy
- **Service:** WinHuntAgent (NSSM-managed)
- **Staging:** NDJSON files in `C:\Program Files\DFI\staging\` every 30s

## Deploy Checklist

Before any deploy:
1. MeshCentral must be running (`python3 skills/health.py`)
2. Windows device must show conn=1 in device list
3. Use `python3 skills/redeploy.py` for code deploys
4. Verify with `python3 skills/status.py` after deploy
