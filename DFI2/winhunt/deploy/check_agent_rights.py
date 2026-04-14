#!/usr/bin/env python3
"""Check MeshAgent rights and logs on Windows 172.16.3.160."""
import winrm

s = winrm.Session("http://172.16.3.160:5985/wsman",
                  auth=("Administrator", "CHANGE_ME"), transport="ntlm",
                  read_timeout_sec=90, operation_timeout_sec=60)

r = s.run_ps(r"""
# MeshAgent service account
Write-Output "=== Mesh Agent Service ==="
Get-WmiObject Win32_Service | Where-Object { $_.Name -like "*mesh*" } |
    Format-List Name, State, StartName, PathName

# Agent directory contents
Write-Output "`n=== Agent directory ==="
Get-ChildItem "C:\Program Files\Mesh Agent" -Name

# Agent directory permissions
Write-Output "`n=== Directory ACL ==="
icacls "C:\Program Files\Mesh Agent"

# Agent process owner
Write-Output "`n=== Agent process ==="
Get-WmiObject Win32_Process -Filter "Name='MeshAgent.exe'" | ForEach-Object {
    $owner = $_.GetOwner()
    Write-Output "PID: $($_.ProcessId) User: $($owner.Domain)\$($owner.User)"
}

# MSH file
Write-Output "`n=== MSH File ==="
Get-Content "C:\Program Files\Mesh Agent\MeshAgent.msh"

# Service privileges
Write-Output "`n=== Service privileges ==="
sc.exe qprivs "Mesh Agent" 2>&1

# Agent log files
Write-Output "`n=== Agent log files ==="
Get-ChildItem "C:\Program Files\Mesh Agent" -Filter *.log -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "--- $($_.Name) (last 30 lines) ---"
    Get-Content $_.FullName -Tail 30 -ErrorAction SilentlyContinue
}

# Check .db files (agent state)
Write-Output "`n=== Agent DB files ==="
Get-ChildItem "C:\Program Files\Mesh Agent" -Filter *.db -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output "$($_.Name) = $($_.Length) bytes"
}

# Application event log for mesh
Write-Output "`n=== Application Event Log (mesh) ==="
Get-WinEvent -FilterHashtable @{LogName='Application'; Level=1,2,3; StartTime=(Get-Date).AddHours(-2)} -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like "*mesh*" -or $_.ProviderName -like "*mesh*" } |
    Format-List TimeCreated, LevelDisplayName, ProviderName, Message

# System event log for service errors
Write-Output "`n=== System Event Log (service) ==="
Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3; StartTime=(Get-Date).AddHours(-2)} -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -like "*mesh*" -or $_.Message -like "*insufficient*" -or $_.Message -like "*denied*" } |
    Format-List TimeCreated, LevelDisplayName, ProviderName, Message
""")

out = r.std_out.decode("utf-8", errors="replace")
print(out)
if r.status_code != 0:
    err = r.std_err.decode("utf-8", errors="replace")
    clean = [l for l in err.split("\n") if not any(x in l for x in ["<Obj","CLIXML","<TN","<MS","<I64","<PR","</","progress"]) and l.strip()]
    if clean:
        print("ERR:", "\n".join(clean[:10]))
