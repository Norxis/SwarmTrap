# Stage 2b: Install Npcap with proper TLS and timeout handling
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # Speeds up Invoke-WebRequest significantly

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Try downloading Npcap
$npcapInstaller = "$env:TEMP\npcap-1.80.exe"

if (-not (Test-Path $npcapInstaller)) {
    Write-Output "Downloading Npcap 1.80..."
    try {
        # Try direct URL first
        Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-1.80.exe" -OutFile $npcapInstaller -UseBasicParsing -TimeoutSec 120
        Write-Output "Downloaded: $((Get-Item $npcapInstaller).Length) bytes"
    } catch {
        Write-Output "Direct download failed: $($_.Exception.Message)"
        Write-Output "Trying alternative method..."
        try {
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile("https://npcap.com/dist/npcap-1.80.exe", $npcapInstaller)
            Write-Output "Downloaded via WebClient: $((Get-Item $npcapInstaller).Length) bytes"
        } catch {
            Write-Output "NPCAP_DOWNLOAD_FAILED: $($_.Exception.Message)"
            exit 1
        }
    }
} else {
    Write-Output "Npcap installer already at $npcapInstaller ($((Get-Item $npcapInstaller).Length) bytes)"
}

Write-Output "Installing Npcap (silent, WinPcap compat mode)..."
$proc = Start-Process -FilePath $npcapInstaller -ArgumentList "/S", "/winpcap_mode=yes", "/loopback_support=yes" -Wait -PassThru -NoNewWindow
Write-Output "Npcap installer exit code: $($proc.ExitCode)"

Start-Sleep -Seconds 3

if (Test-Path "C:\Program Files\Npcap\npcap.sys") {
    Write-Output "Npcap VERIFIED: driver present"
} else {
    Write-Output "Npcap WARNING: driver not found at expected path"
    # Check alternative locations
    Get-ChildItem "C:\Program Files\Npcap" -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "  $($_.Name)" }
    Get-ChildItem "C:\Windows\System32\Npcap" -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "  sys32: $($_.Name)" }
}

Write-Output "STAGE2B_COMPLETE"
