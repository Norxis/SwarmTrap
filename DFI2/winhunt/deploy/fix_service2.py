#!/usr/bin/env python3
"""Fix WinHuntAgent — move config to C:\\DFI\\ (no spaces)."""
import winrm

s = winrm.Session("http://172.16.3.160:5985/wsman",
                  auth=("Administrator", "CHANGE_ME"), transport="ntlm",
                  read_timeout_sec=60, operation_timeout_sec=45)

r = s.run_ps(r"""
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Create C:\DFI as alias — copy config there
New-Item -ItemType Directory -Force -Path "C:\DFI" | Out-Null
Copy-Item "C:\Program Files\DFI\config.json" "C:\DFI\config.json" -Force
Write-Output "Config copied to C:\DFI\config.json"

# Stop and remove old service
nssm stop WinHuntAgent 2>$null
nssm remove WinHuntAgent confirm 2>$null
Start-Sleep 2

# Clear old stderr log
Remove-Item "C:\Program Files\DFI\logs\service_stderr.log" -Force -ErrorAction SilentlyContinue

$py = (Get-Command python).Source
Write-Output "Python: $py"

# Reinstall with no-spaces config path
nssm install WinHuntAgent $py
nssm set WinHuntAgent AppParameters "-m dfi_agent --config C:\DFI\config.json"
nssm set WinHuntAgent AppDirectory "C:\Program Files\DFI\agent"
nssm set WinHuntAgent DisplayName "WinHunt DFI Agent"
nssm set WinHuntAgent Start SERVICE_AUTO_START
nssm set WinHuntAgent AppStdout "C:\DFI\stdout.log"
nssm set WinHuntAgent AppStderr "C:\DFI\stderr.log"
nssm set WinHuntAgent AppRotateFiles 1
nssm set WinHuntAgent AppRotateBytes 10485760

# Verify
Write-Output "`nVerify NSSM params:"
Write-Output "  App: $(nssm get WinHuntAgent Application)"
Write-Output "  Params: $(nssm get WinHuntAgent AppParameters)"
Write-Output "  Dir: $(nssm get WinHuntAgent AppDirectory)"

nssm start WinHuntAgent
Start-Sleep 8
$svc = Get-Service WinHuntAgent
Write-Output "`nService: $($svc.Name) = $($svc.Status)"

# Check logs
if (Test-Path "C:\DFI\stderr.log") {
    Write-Output "`n=== stderr ==="
    Get-Content "C:\DFI\stderr.log" -Tail 15
}
if (Test-Path "C:\Program Files\DFI\logs\agent.log") {
    Write-Output "`n=== agent.log ==="
    Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 15
}
""")

out = r.std_out.decode("utf-8", errors="replace")
print(out)
if r.status_code != 0:
    err = r.std_err.decode("utf-8", errors="replace")
    clean = [l for l in err.split("\n") if "<Obj" not in l and "CLIXML" not in l and l.strip()]
    if clean:
        print("ERR:", "\n".join(clean[:10]))
