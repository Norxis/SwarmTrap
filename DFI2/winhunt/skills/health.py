#!/usr/bin/env python3
"""Quick health check — is everything alive?

Usage: python skills/health.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from mesh import MeshSession


def main():
    with MeshSession() as m:
        # 1. MeshCentral device check
        print("=" * 50)
        print("MeshCentral Health")
        print("=" * 50)
        m.devices()

        # 2. Windows services
        m.ps(r"""$checks = @()

# Services
$wh = Get-Service WinHuntAgent -ErrorAction SilentlyContinue
$ma = Get-Service "Mesh Agent" -ErrorAction SilentlyContinue
$checks += "WinHuntAgent: $($wh.Status)"
$checks += "Mesh Agent:   $($ma.Status)"

# Python process
$py = Get-Process python -ErrorAction SilentlyContinue
$checks += $(if ($py) { "Python PID:   $($py.Id) (Mem: $([math]::Round($py.WorkingSet64/1MB,1))MB)" } else { "Python:       NOT RUNNING" })

# Capture active?
$log = Get-Content "C:\Program Files\DFI\logs\agent.log" -Tail 5 -ErrorAction SilentlyContinue
$lastLine = ($log | Select-Object -Last 1)
$checks += "Last log:     $lastLine"

# Staging accumulation
$staging = Get-ChildItem "C:\Program Files\DFI\staging" -ErrorAction SilentlyContinue
$totalKB = [math]::Round(($staging | Measure-Object Length -Sum).Sum/1KB, 1)
$checks += "Staging:      $($staging.Count) files (${totalKB}KB)"

# DB
$db = Get-Item "C:\Program Files\DFI\data\agent_buffer.db" -ErrorAction SilentlyContinue
$checks += $(if ($db) { "SQLite DB:    $([math]::Round($db.Length/1KB,1))KB" } else { "SQLite DB:    MISSING" })

# Uptime
$checks += "Win Time:     $(Get-Date)"
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$up = (Get-Date) - $boot
$checks += "Uptime:       $($up.Days)d $($up.Hours)h $($up.Minutes)m"

$checks | ForEach-Object { Write-Output $_ }""",
             "Windows 172.16.3.160")


if __name__ == "__main__":
    main()
