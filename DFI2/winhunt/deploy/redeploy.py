#!/usr/bin/env python3
"""Redeploy agent code + config, restart service."""
import winrm

WIN_HOST = "http://172.16.3.160:5985/wsman"

def run_ps(script, label="", timeout=90):
    if label:
        print(f"\n{'=' * 50}")
        print(label)
        print('=' * 50)
    s = winrm.Session(WIN_HOST, auth=("Administrator", "CHANGE_ME"),
                      transport="ntlm", read_timeout_sec=timeout+60, operation_timeout_sec=timeout)
    r = s.run_ps(script)
    out = r.std_out.decode("utf-8", errors="replace").strip()
    if out:
        for line in out.split("\n"):
            print(f"  {line}")
    if r.status_code != 0:
        err = r.std_err.decode("utf-8", errors="replace")
        clean = [l for l in err.split("\n")
                 if not any(x in l for x in ["<Obj","CLIXML","<TN","<MS","<I64","<PR","</","progress"]) and l.strip()]
        if clean:
            print(f"  ERR: {''.join(clean[:5])[:500]}")
    return out

run_ps(r"""
$ProgressPreference = "SilentlyContinue"
nssm stop WinHuntAgent 2>$null
Start-Sleep 3

# Download tarball + config from CT112
New-Item -ItemType Directory -Force -Path "C:\TEMP" | Out-Null
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://172.16.3.112:8888/dfi_agent.tar.gz", "C:\TEMP\dfi_agent.tar.gz")
$size = (Get-Item "C:\TEMP\dfi_agent.tar.gz").Length
Write-Output "Tarball: $size bytes"

# Extract
python -c "import tarfile,shutil,os; shutil.rmtree(r'C:\Program Files\DFI\agent\dfi_agent', True); os.makedirs(r'C:\Program Files\DFI\agent', exist_ok=True); t=tarfile.open(r'C:\TEMP\dfi_agent.tar.gz'); t.extractall(r'C:\Program Files\DFI\agent'); t.close(); print('extracted')"

# Config
$wc.DownloadFile("http://172.16.3.112:8888/dfi_config.json", "C:\DFI\config.json")

# Clean old state
Remove-Item "C:\Program Files\DFI\data\agent_buffer.db*" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\DFI\stderr.log" -Force -ErrorAction SilentlyContinue

# Verify
$files = (Get-ChildItem "C:\Program Files\DFI\agent\dfi_agent" -Filter *.py -ErrorAction SilentlyContinue).Count
Write-Output "Agent files: $files"
python -c "from pathlib import Path; t=Path(r'C:\Program Files\DFI\agent\dfi_agent\capture.py').read_text(); print('SIO_RCVALL' in t and 'NATIVE raw socket' or 'OLD pcapy')"

# Restart
nssm start WinHuntAgent
Start-Sleep 12

$svc = Get-Service WinHuntAgent
Write-Output "`nService: $($svc.Status)"

Write-Output "`n=== agent.log ==="
Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 10 -ErrorAction SilentlyContinue

Write-Output "`n=== stderr ==="
Get-Content "C:\DFI\stderr.log" -Tail 5 -ErrorAction SilentlyContinue
""", "Redeploy agent")
