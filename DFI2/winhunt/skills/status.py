#!/usr/bin/env python3
"""WinHunt full status check via MeshCentral.

Usage: python skills/status.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from mesh import MeshSession


def main():
    with MeshSession() as m:
        m.ps('Get-Service WinHuntAgent,"Mesh Agent" | Format-List Name,Status,StartType',
             "Services")

        m.ps('Get-Content "C:\\Program Files\\DFI\\logs\\agent.log" -Tail 25',
             "Agent Log (last 25)")

        m.ps('Get-Content "C:\\DFI\\stderr.log" -Tail 5',
             "stderr (last 5)")

        m.ps(r"""$files = Get-ChildItem "C:\Program Files\DFI\staging" -ErrorAction SilentlyContinue
$totalKB = [math]::Round(($files | Measure-Object Length -Sum).Sum/1KB, 1)
Write-Output "Files: $($files.Count)  Total: ${totalKB}KB"
$files | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | ForEach-Object { Write-Output "  $($_.Name)  $([math]::Round($_.Length/1KB,1))KB  $($_.LastWriteTime)" }""",
             "Staging Files")

        m.ps(r"""$db = Get-Item "C:\Program Files\DFI\data\agent_buffer.db" -ErrorAction SilentlyContinue
if ($db) { Write-Output "DB: $([math]::Round($db.Length/1KB,1))KB  Modified: $($db.LastWriteTime)" }
Get-Process python -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "PID=$($_.Id) CPU=$($_.CPU) Mem=$([math]::Round($_.WorkingSet64/1MB,1))MB Start=$($_.StartTime)" }""",
             "DB + Process")

        m.ps(r"""$cfg = Get-Content "C:\DFI\config.json" -Raw | ConvertFrom-Json
Write-Output "vm_id=$($cfg.vm_id)  iface=$($cfg.pcap.interface)  port=$($cfg.agent_port)"
Write-Output "Time: $(Get-Date)" """,
             "Config + Time")


if __name__ == "__main__":
    main()
