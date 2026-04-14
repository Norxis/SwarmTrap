# Stage 1: Install Python 3.12 silently
$ErrorActionPreference = "Stop"

# Disable Store app alias for python
$aliases = @(
    "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python.exe",
    "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\python3.exe"
)
foreach ($alias in $aliases) {
    $path = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\$alias"
    if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
}

# Download Python 3.12 installer
$pyUrl = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe"
$pyInstaller = "$env:TEMP\python-3.12.10-amd64.exe"

Write-Output "Downloading Python 3.12.10..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $pyUrl -OutFile $pyInstaller -UseBasicParsing

Write-Output "Installing Python 3.12.10 (silent, all users, add to PATH)..."
$proc = Start-Process -FilePath $pyInstaller -ArgumentList @(
    "/quiet",
    "InstallAllUsers=1",
    "PrependPath=1",
    "Include_pip=1",
    "Include_test=0",
    "Include_doc=0",
    "Include_launcher=1",
    "AssociateFiles=1"
) -Wait -PassThru

if ($proc.ExitCode -ne 0) {
    throw "Python installer failed with exit code $($proc.ExitCode)"
}

# Refresh PATH
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

# Verify
$pyPath = (Get-Command python -ErrorAction SilentlyContinue).Source
$pyVer = & python --version 2>&1
Write-Output "Python installed: $pyVer at $pyPath"

# Upgrade pip
& python -m pip install --upgrade pip 2>&1 | Select-Object -Last 2
Write-Output "STAGE1_COMPLETE"
