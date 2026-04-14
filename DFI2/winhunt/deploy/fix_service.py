#!/usr/bin/env python3
"""Fix WinHuntAgent service — config path quoting."""
import winrm

s = winrm.Session("http://172.16.3.160:5985/wsman",
                  auth=("Administrator", "CHANGE_ME"), transport="ntlm",
                  read_timeout_sec=60, operation_timeout_sec=45)

r = s.run_ps(r"""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Stop and remove old service
nssm stop WinHuntAgent 2>$null
nssm remove WinHuntAgent confirm 2>$null
Start-Sleep 2

$py = (Get-Command python).Source
Write-Output "Python: $py"

# Install with AppParameters to handle spaces correctly
nssm install WinHuntAgent $py
nssm set WinHuntAgent AppParameters '-m dfi_agent --config "C:\Program Files\DFI\config.json"'
nssm set WinHuntAgent AppDirectory "C:\Program Files\DFI\agent"
nssm set WinHuntAgent DisplayName "WinHunt DFI Agent"
nssm set WinHuntAgent Description "DFI Windows capture agent"
nssm set WinHuntAgent Start SERVICE_AUTO_START
nssm set WinHuntAgent AppStdout "C:\Program Files\DFI\logs\service_stdout.log"
nssm set WinHuntAgent AppStderr "C:\Program Files\DFI\logs\service_stderr.log"
nssm set WinHuntAgent AppRotateFiles 1
nssm set WinHuntAgent AppRotateBytes 10485760

# Verify parameters before starting
Write-Output "Parameters set:"
nssm get WinHuntAgent Application
nssm get WinHuntAgent AppParameters
nssm get WinHuntAgent AppDirectory

nssm start WinHuntAgent
Start-Sleep 8
$svc = Get-Service WinHuntAgent
Write-Output "Service: $($svc.Name) = $($svc.Status)"

# Check logs
if (Test-Path "C:\Program Files\DFI\logs\service_stderr.log") {
    Write-Output "`n=== stderr log ==="
    Get-Content "C:\Program Files\DFI\logs\service_stderr.log" -Tail 10
}
if (Test-Path "C:\Program Files\DFI\logs\agent.log") {
    Write-Output "`n=== agent.log ==="
    Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 10
}
""")

out = r.std_out.decode("utf-8", errors="replace")
print(out)
if r.status_code != 0:
    err = r.std_err.decode("utf-8", errors="replace")
    clean = [l for l in err.split("\n") if "<Obj" not in l and "CLIXML" not in l and l.strip()]
    if clean:
        print("ERR:", "\n".join(clean[:10]))
