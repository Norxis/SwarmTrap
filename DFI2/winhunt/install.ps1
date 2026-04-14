param(
  [string]$InstallRoot = "C:\Program Files\DFI",
  [string]$PythonExe = "",
  [string]$ConfigPath = "C:\Program Files\DFI\config.json",
  [string]$VmId = "win-honey-01",
  [string]$Interface = "Ethernet"
)

$ErrorActionPreference = "Stop"

function Resolve-PythonExe {
  param([string]$Hint)
  $candidates = @()
  if ($Hint) { $candidates += $Hint }
  $candidates += @("python", "py -3.12", "py -3", "py")
  foreach ($cand in $candidates) {
    try {
      if ($cand -like "py *") {
        cmd /c "$cand -c ""import sys; print(sys.executable)""" | Out-Null
        if ($LASTEXITCODE -eq 0) { return $cand }
      } else {
        & $cand -c "import sys; print(sys.executable)" | Out-Null
        if ($LASTEXITCODE -eq 0) { return $cand }
      }
    } catch {}
  }
  throw "Python interpreter not found. Pass -PythonExe with full path."
}

New-Item -ItemType Directory -Force -Path "$InstallRoot\data" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallRoot\logs" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallRoot\staging" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallRoot\agent" | Out-Null

$agentSrc = Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item -Recurse -Force "$agentSrc\dfi_agent" "$InstallRoot\agent\"

$PythonExe = Resolve-PythonExe -Hint $PythonExe

$config = @{
  vm_id = $VmId
  buffer_path = "$InstallRoot\data\agent_buffer.db"
  log_dir = "$InstallRoot\logs"
  log_level = "INFO"
  retention_days = 7
  pcap = @{
    enabled = $true
    interface = $Interface
    snap_len = 256
    buffer_mb = 16
    bpf_filter = ""
    flow_timeout_s = 120
    flow_drain_rst_s = 2
    flow_drain_fin_s = 5
    max_active_flows = 50000
    max_event_pkts = 128
    max_flow_pkts = 10000
    capture_source = 1
    local_networks = @("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
  }
  evidence = @{
    enabled = $true
    channels = @(
      "Security",
      "System",
      "Application",
      "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
      "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
      "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
      "Microsoft-Windows-WinRM/Operational",
      "Microsoft-Windows-PowerShell/Operational",
      "Microsoft-Windows-Windows Defender/Operational",
      "Microsoft-Windows-Sysmon/Operational"
    )
    iis_log_dir = "C:\inetpub\logs\LogFiles\W3SVC1"
    logon_map_ttl_hours = 24
    suspicious_patterns = @("(cmd|powershell|pwsh).*(/c|/k|-enc)")
    download_patterns = @("certutil\\s.*-urlcache")
  }
  exporter = @{
    enabled = $true
    staging_dir = "$InstallRoot\staging"
    export_interval_s = 30
    max_rows_per_file = 10000
    file_prefix = "dfi"
    retention_hours = 24
  }
  services = @{
    rdp = @{ port = 3389; enabled = $true }
    smb = @{ port = 445; enabled = $true }
    winrm = @{ ports = @(5985,5986); enabled = $true }
    mssql = @{ port = 1433; enabled = $true }
    iis_http = @{ port = 80; enabled = $true }
    iis_https = @{ port = 443; enabled = $true }
  }
}

$config | ConvertTo-Json -Depth 8 | Set-Content -Path $ConfigPath -Encoding UTF8

$svcName = "WinHuntAgent"
$pyCmd = $PythonExe
if ($pyCmd -notlike "py*") { $pyCmd = "`"$pyCmd`"" }
$cmd = "$pyCmd -m dfi_agent --config `"$ConfigPath`""
$cwd = "$InstallRoot\agent"

if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
  sc.exe stop $svcName | Out-Null
  sc.exe delete $svcName | Out-Null
  Start-Sleep -Seconds 1
}

sc.exe create $svcName binPath= "cmd /c cd /d `"$cwd`" && $cmd" start= auto | Out-Null
sc.exe description $svcName "WinHunt DFI capture agent" | Out-Null
sc.exe start $svcName | Out-Null

Write-Host "Installed $svcName with config at $ConfigPath"
