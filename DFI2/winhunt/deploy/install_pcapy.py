#!/usr/bin/env python3
"""Install pcapy-ng: get MSVC build tools + Npcap SDK, then build."""
import winrm
import time

WIN_HOST = "http://172.16.3.160:5985/wsman"

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

# Step 1: Download and install VS Build Tools (C++ compiler)
run_ps(r"""
$ProgressPreference = "SilentlyContinue"

# Download VS Build Tools installer
Write-Output "Downloading VS Build Tools..."
$url = "https://aka.ms/vs/17/release/vs_BuildTools.exe"
Invoke-WebRequest -Uri $url -OutFile "C:\TEMP\vs_buildtools.exe" -UseBasicParsing
$size = (Get-Item "C:\TEMP\vs_buildtools.exe").Length
Write-Output "Downloaded: $size bytes"
""", "Download VS Build Tools", timeout=120)

# Install with just C++ build tools (minimal)
run_ps(r"""
Write-Output "Installing VS Build Tools (C++ workload)..."
Write-Output "This takes several minutes..."
$proc = Start-Process -FilePath "C:\TEMP\vs_buildtools.exe" -ArgumentList "--quiet --wait --norestart --nocache --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended" -Wait -NoNewWindow -PassThru
Write-Output "Exit code: $($proc.ExitCode)"
""", "Install VS Build Tools", timeout=600)

# Step 2: Download Npcap SDK
run_ps(r"""
$ProgressPreference = "SilentlyContinue"
Write-Output "Downloading Npcap SDK..."
$url = "https://npcap.com/dist/npcap-sdk-1.13.zip"
Invoke-WebRequest -Uri $url -OutFile "C:\TEMP\npcap-sdk.zip" -UseBasicParsing
$size = (Get-Item "C:\TEMP\npcap-sdk.zip").Length
Write-Output "Downloaded: $size bytes"

# Extract SDK
Expand-Archive -Path "C:\TEMP\npcap-sdk.zip" -DestinationPath "C:\npcap-sdk" -Force
Write-Output "Extracted to C:\npcap-sdk"
Get-ChildItem "C:\npcap-sdk" -Name
""", "Download + extract Npcap SDK", timeout=120)

# Step 3: Build and install pcapy-ng with SDK paths
run_ps(r"""
# Find MSVC tools
$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vsWhere) {
    $installPath = & $vsWhere -latest -property installationPath 2>$null
    Write-Output "VS Install: $installPath"
}

# Set environment for building
$env:INCLUDE = "C:\npcap-sdk\Include"
$env:LIB = "C:\npcap-sdk\Lib\x64"

Write-Output "`nInstalling pcapy-ng..."
python -m pip install pcapy-ng --no-cache-dir 2>&1

Write-Output "`n=== Import test ==="
python -c "import pcapy; devs = pcapy.findalldevs(); print(f'pcapy OK: {len(devs)} devices'); [print(f'  {d}') for d in devs]" 2>&1
""", "Build pcapy-ng", timeout=300)
