# Stage 2: Install Npcap + NSSM
$ErrorActionPreference = "Stop"

# Refresh PATH from Stage 1
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

# --- NSSM ---
$nssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$nssmZip = "$env:TEMP\nssm-2.24.zip"
$nssmDir = "$env:TEMP\nssm-2.24"

Write-Output "Downloading NSSM 2.24..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $nssmUrl -OutFile $nssmZip -UseBasicParsing

Write-Output "Extracting NSSM..."
Expand-Archive -Path $nssmZip -DestinationPath $env:TEMP -Force
Copy-Item "$nssmDir\win64\nssm.exe" "C:\Windows\System32\nssm.exe" -Force
Write-Output "NSSM installed: $(nssm version 2>&1)"

# --- Npcap ---
# Npcap OEM silent install (lab use)
$npcapUrl = "https://npcap.com/dist/npcap-1.80.exe"
$npcapInstaller = "$env:TEMP\npcap-1.80.exe"

Write-Output "Downloading Npcap 1.80..."
Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller -UseBasicParsing

Write-Output "Installing Npcap (silent)..."
$proc = Start-Process -FilePath $npcapInstaller -ArgumentList @(
    "/S",
    "/winpcap_mode=yes",
    "/loopback_support=yes"
) -Wait -PassThru

if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 1) {
    Write-Warning "Npcap installer returned exit code $($proc.ExitCode) - may need manual install"
} else {
    Write-Output "Npcap installed"
}

# Verify Npcap
if (Test-Path "C:\Program Files\Npcap\npcap.sys") {
    Write-Output "Npcap verified: C:\Program Files\Npcap\npcap.sys exists"
} else {
    Write-Warning "Npcap driver not found at expected path"
}

Write-Output "STAGE2_COMPLETE"
