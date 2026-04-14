#!/usr/bin/env python3
"""Manage NDJSON staging directory on Windows via MeshCentral.

Usage:
    python skills/staging.py             # show staging stats
    python skills/staging.py --clean     # delete all staging files
    python skills/staging.py --sample    # show first 3 lines of newest file
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from mesh import MeshSession


def main():
    action = "stats"
    if "--clean" in sys.argv:
        action = "clean"
    elif "--sample" in sys.argv:
        action = "sample"

    with MeshSession() as m:
        if action == "stats":
            m.ps(r"""$dir = "C:\Program Files\DFI\staging"
$files = Get-ChildItem $dir -ErrorAction SilentlyContinue
$flows = $files | Where-Object { $_.Name -like "dfi_flows_*" }
$events = $files | Where-Object { $_.Name -like "dfi_events_*" }
$totalKB = [math]::Round(($files | Measure-Object Length -Sum).Sum/1KB, 1)
$flowsKB = [math]::Round(($flows | Measure-Object Length -Sum).Sum/1KB, 1)
$eventsKB = [math]::Round(($events | Measure-Object Length -Sum).Sum/1KB, 1)

Write-Output "Total:  $($files.Count) files  ${totalKB}KB"
Write-Output "Flows:  $($flows.Count) files  ${flowsKB}KB"
Write-Output "Events: $($events.Count) files  ${eventsKB}KB"

Write-Output "`n=== Latest 5 ==="
$files | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | ForEach-Object {
    Write-Output "  $($_.Name)  $([math]::Round($_.Length/1KB,1))KB  $($_.LastWriteTime)"
}

Write-Output "`n=== Oldest 3 ==="
$files | Sort-Object LastWriteTime | Select-Object -First 3 | ForEach-Object {
    Write-Output "  $($_.Name)  $([math]::Round($_.Length/1KB,1))KB  $($_.LastWriteTime)"
}""", "Staging Stats")

        elif action == "clean":
            m.ps(r"""$dir = "C:\Program Files\DFI\staging"
$before = (Get-ChildItem $dir -ErrorAction SilentlyContinue).Count
Remove-Item "$dir\*" -Force -ErrorAction SilentlyContinue
$after = (Get-ChildItem $dir -ErrorAction SilentlyContinue).Count
Write-Output "Deleted $($before - $after) files ($after remaining)" """,
                 "Clean Staging")

        elif action == "sample":
            m.ps(r"""$dir = "C:\Program Files\DFI\staging"
$latest = Get-ChildItem $dir -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 2
foreach ($f in $latest) {
    Write-Output "=== $($f.Name) ==="
    Get-Content $f.FullName -TotalCount 3
    Write-Output ""
}""", "Sample Data")


if __name__ == "__main__":
    main()
