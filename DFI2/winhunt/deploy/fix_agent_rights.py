#!/usr/bin/env python3
"""Fix MeshAgent interactive service flag + insufficient rights."""
import winrm

s = winrm.Session("http://172.16.3.160:5985/wsman",
                  auth=("Administrator", "CHANGE_ME"), transport="ntlm",
                  read_timeout_sec=90, operation_timeout_sec=60)

r = s.run_ps(r"""
# Current service type
Write-Output "=== Current service config ==="
sc.exe qc "Mesh Agent"

# Fix: Remove interactive flag (change type from 0x110 to 0x10)
Write-Output "`n=== Fix: Remove interactive service flag ==="
sc.exe config "Mesh Agent" type= own
Write-Output "Result: $LASTEXITCODE"

# Verify fix
Write-Output "`n=== Updated service config ==="
sc.exe qc "Mesh Agent"

# Restart service
Write-Output "`n=== Restart Mesh Agent ==="
Restart-Service "Mesh Agent" -Force
Start-Sleep 8
Get-Service "Mesh Agent" | Format-Table Name, Status -AutoSize

# Check connections
Write-Output "`n=== Connections to 172.16.3.112 ==="
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq "172.16.3.112" } |
    Format-Table LocalPort, RemotePort, State -AutoSize

# Check event log for new errors after fix
Write-Output "`n=== Recent System errors (last 2 min) ==="
Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3; StartTime=(Get-Date).AddMinutes(-2)} -MaxEvents 10 -ErrorAction SilentlyContinue |
    Format-List TimeCreated, LevelDisplayName, ProviderName, Message
""")

out = r.std_out.decode("utf-8", errors="replace")
print(out)
if r.status_code != 0:
    err = r.std_err.decode("utf-8", errors="replace")
    clean = [l for l in err.split("\n") if not any(x in l for x in ["<Obj","CLIXML","<TN","<MS","<I64","<PR","</","progress"]) and l.strip()]
    if clean:
        print("ERR:", "\n".join(clean[:10]))
