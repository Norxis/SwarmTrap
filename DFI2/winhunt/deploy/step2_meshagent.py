#!/usr/bin/env python3
"""Step 2: Install MeshCentral agent on Windows Server 172.16.3.160."""
import paramiko
import winrm
import time
import re
import sys

PV1 = "192.168.0.100"
PV1_USER = "root"
PV1_PASS = "CHANGE_ME"
MESH_USER = "admin"
MESH_PASS = "CHANGE_ME"

WIN_HOST = "http://172.16.3.160:5985/wsman"
WIN_USER = "Administrator"
WIN_PASS = "CHANGE_ME"


def pv1_run(client, cmd, timeout=60):
    print(f"\n[PV1] $ {cmd[:200]}")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    rc = stdout.channel.recv_exit_status()
    if out:
        for line in out.split("\n")[-20:]:
            print(f"  {line}")
    if rc != 0 and err:
        print(f"  ERR(rc={rc}): {err[:300]}")
    return out, err, rc


def win_run(script, label=""):
    if label:
        print(f"\n[WIN] [{label}]")
    s = winrm.Session(WIN_HOST, auth=(WIN_USER, WIN_PASS), transport="ntlm")
    r = s.run_ps(script)
    out = r.std_out.decode("utf-8", errors="replace").strip()
    err_raw = r.std_err.decode("utf-8", errors="replace").strip()
    # Filter CLIXML noise
    err = "\n".join(
        l for l in err_raw.split("\n")
        if "<Obj" not in l and "CLIXML" not in l and "Preparing modules" not in l
        and "progress" not in l.lower() and l.strip()
    )
    if out:
        for line in out.split("\n")[-20:]:
            print(f"  {line}")
    if r.status_code != 0 and err:
        print(f"  ERR: {err[:300]}")
    return out, err, r.status_code


def main():
    print("=" * 60)
    print("PART A: Get MeshCentral agent install info")
    print("=" * 60)

    pv1 = paramiko.SSHClient()
    pv1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pv1.connect(PV1, username=PV1_USER, password=PV1_PASS, timeout=10)

    meshctrl = "/opt/meshcentral/node_modules/meshcentral/meshctrl.js"
    base = f'--url wss://localhost --loginuser {MESH_USER} --loginpass "{MESH_PASS}"'

    # List device groups — get the mesh ID
    out, _, _ = pv1_run(pv1, f'pct exec 112 -- node {meshctrl} {base} listdevicegroups 2>&1')

    # Parse: format is "MESHID", "GroupName"
    mesh_id = None
    for line in out.split("\n"):
        if "WinHunt-Test" in line:
            # Extract quoted ID
            match = re.search(r'"([^"]+)".*WinHunt-Test', line)
            if match:
                mesh_id = match.group(1)
                break

    if not mesh_id:
        print("Device group not found, creating...")
        out, _, _ = pv1_run(pv1, f'pct exec 112 -- node {meshctrl} {base} adddevicegroup --name "WinHunt-Test" 2>&1')
        # Parse from create output: "ok mesh//MESHID"
        match = re.search(r'mesh//(\S+)', out)
        if match:
            mesh_id = match.group(1)
        else:
            print(f"FATAL: Cannot get mesh ID. Output: {out}")
            sys.exit(1)

    print(f"\n  Mesh ID: {mesh_id}")

    # Get server cert hash (SHA384)
    out, _, _ = pv1_run(pv1, 'pct exec 112 -- openssl x509 -in /opt/meshcentral/meshcentral-data/webserver-cert-public.crt -fingerprint -sha384 -noout 2>/dev/null')
    # Extract hex hash, remove colons
    hash_match = re.search(r'=([A-Fa-f0-9:]+)', out)
    server_hash = hash_match.group(1).replace(":", "").upper() if hash_match else ""
    print(f"  Server hash: {server_hash[:40]}...")

    # Also try to get the install script directly from MeshCentral
    # MeshCentral serves a PowerShell install script at a specific URL
    out, _, _ = pv1_run(pv1,
        f'pct exec 112 -- curl -sk "https://localhost/meshagents?script=1&meshid=mesh//{mesh_id}" 2>/dev/null | head -5')
    print(f"  Install script preview: {out[:200] if out else 'empty'}")

    # Get the Windows agent download URL info
    # MeshCentral agent type 4 = Windows x64
    out, _, _ = pv1_run(pv1,
        'pct exec 112 -- curl -sk "https://localhost/meshagents?id=4" -o /tmp/meshagent.exe -w "%{size_download} bytes, HTTP %{http_code}" 2>/dev/null')
    pv1_run(pv1, 'pct exec 112 -- ls -la /tmp/meshagent.exe 2>/dev/null')

    pv1.close()

    # ===== PART B: Install on Windows =====
    print("\n" + "=" * 60)
    print("PART B: Install MeshAgent on 172.16.3.160")
    print("=" * 60)

    # Download the agent directly from MeshCentral (192.168.0.112)
    win_run(r"""
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$agentPath = "$env:TEMP\meshagent.exe"

Write-Output "Downloading MeshAgent from https://192.168.0.112..."
try {
    # Bypass SSL cert validation for self-signed
    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
        add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile("https://192.168.0.112/meshagents?id=4", $agentPath)
    $size = (Get-Item $agentPath).Length
    Write-Output "Downloaded: $size bytes to $agentPath"
} catch {
    Write-Output "WebClient failed: $($_.Exception.Message)"
    Write-Output "Trying curl..."
    curl.exe -sk -o $agentPath "https://192.168.0.112/meshagents?id=4" 2>&1
    if (Test-Path $agentPath) {
        Write-Output "curl download: $((Get-Item $agentPath).Length) bytes"
    } else {
        Write-Output "DOWNLOAD FAILED"
        exit 1
    }
}
    """, "Download agent binary")

    # Write MSH file with connection info
    msh = f"""MeshName=WinHunt MeshCentral
MeshType=2
MeshID=0x{mesh_id}
ServerID={server_hash}
MeshServer=wss://192.168.0.112:443/agent.ashx
"""
    win_run(f"""
$msh = @'
{msh.strip()}
'@
Set-Content -Path "$env:TEMP\\meshagent.msh" -Value $msh -Encoding ASCII -NoNewline
Write-Output "MSH file written:"
Get-Content "$env:TEMP\\meshagent.msh"
    """, "Write MSH config")

    # Install the agent
    win_run(r"""
$agentPath = "$env:TEMP\meshagent.exe"
$mshPath = "$env:TEMP\meshagent.msh"

if (-not (Test-Path $agentPath)) {
    Write-Output "ERROR: meshagent.exe not found at $agentPath"
    exit 1
}

Write-Output "File size: $((Get-Item $agentPath).Length) bytes"
Write-Output "Installing MeshAgent..."

# Copy to final location first
$installDir = "C:\Program Files\Mesh Agent"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item $agentPath "$installDir\MeshAgent.exe" -Force
Copy-Item $mshPath "$installDir\MeshAgent.msh" -Force

# Run installer
$proc = Start-Process -FilePath "$installDir\MeshAgent.exe" -ArgumentList "-install" -Wait -PassThru -NoNewWindow
Write-Output "Install exit code: $($proc.ExitCode)"

Start-Sleep -Seconds 8

# Check service
$svc = Get-Service | Where-Object { $_.Name -like "*mesh*" -or $_.DisplayName -like "*mesh*" }
if ($svc) {
    foreach ($s in $svc) {
        Write-Output "Service: $($s.Name) [$($s.DisplayName)] = $($s.Status)"
    }
} else {
    Write-Output "No mesh service found. Checking processes..."
    Get-Process | Where-Object { $_.Name -like "*mesh*" } | ForEach-Object {
        Write-Output "Process: $($_.Name) PID=$($_.Id)"
    }
}

# List install directory
Write-Output ""
Write-Output "Install dir contents:"
Get-ChildItem "$installDir" -Name 2>$null
    """, "Install agent")

    # ===== PART C: Verify connection =====
    print("\n" + "=" * 60)
    print("PART C: Verify agent connection")
    print("=" * 60)

    time.sleep(5)

    # Check from MeshCentral server
    pv1 = paramiko.SSHClient()
    pv1.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pv1.connect(PV1, username=PV1_USER, password=PV1_PASS, timeout=10)

    pv1_run(pv1, f'pct exec 112 -- node {meshctrl} {base} listdevices --group "WinHunt-Test" 2>&1')

    pv1.close()

    print("\n" + "=" * 60)
    print("Step 2 complete")
    print("Check https://192.168.0.112 for the device in WinHunt-Test")
    print("=" * 60)


if __name__ == "__main__":
    main()
