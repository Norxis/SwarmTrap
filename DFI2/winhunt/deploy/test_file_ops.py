#!/usr/bin/env python3
"""Test file transfer, delete, modify from CT112 to Windows 160 via MeshCentral."""
import paramiko
import json
import time

PV1 = "192.168.0.100"
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(PV1, username="root", password="CHANGE_ME", timeout=10)

meshctrl = "/opt/meshcentral/node_modules/meshcentral/meshctrl.js"
mbase = '--url wss://localhost --loginuser admin --loginpass "CHANGE_ME"'

def run(cmd, timeout=30):
    print(f"\n$ {cmd[:200]}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out: print(f"  {out}")
    if err: print(f"  ERR: {err[:300]}")
    return out

def mc_run(node_id, ps_cmd, label=""):
    if label:
        print(f"\n{'=' * 50}")
        print(label)
        print('=' * 50)
    # Escape for nested shell
    escaped = ps_cmd.replace('"', '\\"')
    run(f'pct exec 112 -- node {meshctrl} {mbase} runcommand --id "{node_id}" --run "{escaped}" --powershell 2>&1')

# Get node ID
out = run(f'pct exec 112 -- node {meshctrl} {mbase} listdevices --json 2>&1')
devices = json.loads(out)
node_id = devices[0]["_id"]
print(f"\nDevice: {devices[0]['name']} ({node_id})")

# Also set up WinRM for verification
import winrm
ws = winrm.Session("http://172.16.3.160:5985/wsman",
                   auth=("Administrator", "CHANGE_ME"), transport="ntlm",
                   read_timeout_sec=60, operation_timeout_sec=45)

def win_verify(ps, label=""):
    if label:
        print(f"\n  [Verify: {label}]")
    r = ws.run_ps(ps)
    out = r.std_out.decode("utf-8", errors="replace").strip()
    if out:
        for line in out.split("\n"):
            print(f"    {line}")
    return out

# ============================================================
# TEST 1: Create file on Windows via MeshCentral
# ============================================================
mc_run(node_id,
       "Set-Content -Path C:\\Users\\Public\\mc_test.txt -Value 'Hello from MeshCentral CT112 - file transfer test'",
       "TEST 1: Create file on Windows via MeshCentral")
time.sleep(3)
win_verify(r"Get-Content 'C:\Users\Public\mc_test.txt'", "File content")

# ============================================================
# TEST 2: Create multi-line file
# ============================================================
mc_run(node_id,
       "@('Line 1: MeshCentral test','Line 2: timestamp ' + (Get-Date).ToString(),'Line 3: from CT112') | Set-Content C:\\Users\\Public\\mc_multiline.txt",
       "TEST 2: Create multi-line file")
time.sleep(3)
win_verify(r"Get-Content 'C:\Users\Public\mc_multiline.txt'", "Multi-line content")

# ============================================================
# TEST 3: Modify file (append)
# ============================================================
mc_run(node_id,
       "Add-Content -Path C:\\Users\\Public\\mc_test.txt -Value 'Appended line from MeshCentral'",
       "TEST 3: Modify file (append)")
time.sleep(3)
win_verify(r"Get-Content 'C:\Users\Public\mc_test.txt'", "After append")

# ============================================================
# TEST 4: Modify file (replace content)
# ============================================================
mc_run(node_id,
       "(Get-Content C:\\Users\\Public\\mc_test.txt) -replace 'Hello','MODIFIED' | Set-Content C:\\Users\\Public\\mc_test.txt",
       "TEST 4: Modify file (replace content)")
time.sleep(3)
win_verify(r"Get-Content 'C:\Users\Public\mc_test.txt'", "After replace")

# ============================================================
# TEST 5: Create directory + file
# ============================================================
mc_run(node_id,
       "New-Item -ItemType Directory -Force -Path C:\\Users\\Public\\mc_testdir | Out-Null; Set-Content C:\\Users\\Public\\mc_testdir\\nested.txt -Value 'Nested file test'",
       "TEST 5: Create directory + nested file")
time.sleep(3)
win_verify(r"Get-ChildItem 'C:\Users\Public\mc_testdir' -Name; Get-Content 'C:\Users\Public\mc_testdir\nested.txt'",
           "Directory listing + content")

# ============================================================
# TEST 6: Delete file
# ============================================================
mc_run(node_id,
       "Remove-Item C:\\Users\\Public\\mc_test.txt -Force",
       "TEST 6: Delete file")
time.sleep(3)
win_verify(r"Test-Path 'C:\Users\Public\mc_test.txt'", "File exists after delete (should be False)")

# ============================================================
# TEST 7: Delete directory recursively
# ============================================================
mc_run(node_id,
       "Remove-Item C:\\Users\\Public\\mc_testdir -Recurse -Force",
       "TEST 7: Delete directory recursively")
time.sleep(3)
win_verify(r"Test-Path 'C:\Users\Public\mc_testdir'", "Dir exists after delete (should be False)")

# ============================================================
# TEST 8: Upload binary content (base64 round-trip)
# ============================================================
mc_run(node_id,
       "$bytes = [byte[]](0x50,0x4B,0x03,0x04,0x00,0x00); [System.IO.File]::WriteAllBytes('C:\\Users\\Public\\mc_binary.bin', $bytes)",
       "TEST 8: Write binary content")
time.sleep(3)
win_verify(r"""
$b = [System.IO.File]::ReadAllBytes('C:\Users\Public\mc_binary.bin')
$hex = ($b | ForEach-Object { '0x{0:X2}' -f $_ }) -join ' '
Write-Output "Size: $($b.Length) bytes, Hex: $hex"
""", "Binary file verification")

# ============================================================
# Cleanup
# ============================================================
mc_run(node_id,
       "Remove-Item C:\\Users\\Public\\mc_multiline.txt -Force -ErrorAction SilentlyContinue; Remove-Item C:\\Users\\Public\\mc_binary.bin -Force -ErrorAction SilentlyContinue",
       "CLEANUP: Remove test files")
time.sleep(3)
win_verify(r"""
$files = @('C:\Users\Public\mc_test.txt','C:\Users\Public\mc_multiline.txt','C:\Users\Public\mc_binary.bin','C:\Users\Public\mc_testdir')
foreach ($f in $files) { Write-Output "$f exists: $(Test-Path $f)" }
""", "All test files cleaned up")

c.close()
print("\n" + "=" * 50)
print("ALL TESTS COMPLETE")
print("=" * 50)
