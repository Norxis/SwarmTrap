#!/usr/bin/env python3
"""Install pcapy-ng: download deps via CT112, build on Windows."""
import paramiko
import winrm
import time

PV1 = "192.168.0.100"
MESH_IP = "172.16.3.112"
WIN_HOST = "http://172.16.3.160:5985/wsman"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(PV1, username="root", password="CHANGE_ME", timeout=10)

def pv1_run(cmd, timeout=60):
    print(f"\n[PV1] $ {cmd[:200]}")
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out:
        for line in out.split("\n")[-10:]:
            print(f"  {line}")
    if err:
        print(f"  ERR: {err[:300]}")
    return out

def run_ps(script, label="", timeout=300):
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

# Step 1: Download Npcap SDK and VS Build Tools on CT112
print("=" * 60)
print("Download build deps on CT112")
print("=" * 60)

pv1_run('pct exec 112 -- curl -sL "https://npcap.com/dist/npcap-sdk-1.13.zip" -o /tmp/npcap-sdk.zip -w "size=%{size_download}"', timeout=60)
pv1_run('pct exec 112 -- ls -la /tmp/npcap-sdk.zip')

pv1_run('pct exec 112 -- curl -sL "https://aka.ms/vs/17/release/vs_BuildTools.exe" -o /tmp/vs_buildtools.exe -w "size=%{size_download}" -L', timeout=120)
pv1_run('pct exec 112 -- ls -la /tmp/vs_buildtools.exe')

# Start HTTP server
pv1_run('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')
pv1_run('pct exec 112 -- bash -c "setsid python3 -m http.server 8888 --directory /tmp </dev/null >/dev/null 2>&1 & sleep 1 && ss -tlnp | grep 8888"')

# Step 2: Download on Windows via CT112 HTTP
run_ps(f"""
$ProgressPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force -Path C:\\TEMP | Out-Null

# Download Npcap SDK
Write-Output "Downloading Npcap SDK..."
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("http://{MESH_IP}:8888/npcap-sdk.zip", "C:\\TEMP\\npcap-sdk.zip")
$size = (Get-Item "C:\\TEMP\\npcap-sdk.zip").Length
Write-Output "Npcap SDK: $size bytes"

# Extract SDK
Expand-Archive -Path "C:\\TEMP\\npcap-sdk.zip" -DestinationPath "C:\\npcap-sdk" -Force
Write-Output "Extracted to C:\\npcap-sdk"
Get-ChildItem "C:\\npcap-sdk" -Name

# Download VS Build Tools
Write-Output "`nDownloading VS Build Tools..."
$wc.DownloadFile("http://{MESH_IP}:8888/vs_buildtools.exe", "C:\\TEMP\\vs_buildtools.exe")
$size = (Get-Item "C:\\TEMP\\vs_buildtools.exe").Length
Write-Output "VS Build Tools: $size bytes"
""", "Download deps to Windows", timeout=120)

# Step 3: Install VS Build Tools (C++ workload only)
run_ps(r"""
Write-Output "Installing VS Build Tools with C++ workload..."
Write-Output "(This takes 5-10 minutes)"
$proc = Start-Process -FilePath "C:\TEMP\vs_buildtools.exe" `
    -ArgumentList "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" `
    -Wait -NoNewWindow -PassThru
Write-Output "VS Build Tools exit code: $($proc.ExitCode)"

# Verify MSVC is installed
$clPath = Get-ChildItem "C:\Program Files (x86)\Microsoft Visual Studio" -Recurse -Filter "cl.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($clPath) { Write-Output "cl.exe found: $($clPath.FullName)" }
else { Write-Output "cl.exe NOT found" }
""", "Install VS Build Tools", timeout=600)

# Step 4: Build pcapy-ng
run_ps(r"""
# Set environment for MSVC + Npcap SDK
$env:INCLUDE = "C:\npcap-sdk\Include;" + $env:INCLUDE
$env:LIB = "C:\npcap-sdk\Lib\x64;" + $env:LIB

# Find and activate MSVC environment
$vcvars = Get-ChildItem "C:\Program Files (x86)\Microsoft Visual Studio" -Recurse -Filter "vcvars64.bat" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($vcvars) {
    Write-Output "vcvars64: $($vcvars.FullName)"
    # Source the environment
    cmd /c "`"$($vcvars.FullName)`" && set" | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($matches[1], $matches[2])
        }
    }
}

Write-Output "`nBuilding pcapy-ng..."
python -m pip install pcapy-ng --no-cache-dir 2>&1

Write-Output "`n=== Import test ==="
python -c "import pcapy; devs = pcapy.findalldevs(); print(f'pcapy OK: {len(devs)} devices'); [print(f'  {d}') for d in devs]" 2>&1
""", "Build + install pcapy-ng", timeout=300)

# If pcapy works, restart agent
run_ps(r"""
$result = python -c "import pcapy; print('OK')" 2>&1
if ($result -eq "OK") {
    Write-Output "pcapy works! Restarting agent..."
    nssm restart WinHuntAgent
    Start-Sleep 12
    Get-Content "C:\DFI\stderr.log" -Tail 10
} else {
    Write-Output "pcapy still not working: $result"
}
""", "Restart agent if pcapy works")

pv1_run('pct exec 112 -- bash -c "pkill -f http.server 2>/dev/null; true"')
c.close()
