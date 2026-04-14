$info = @{}
$info["os"] = (Get-CimInstance Win32_OperatingSystem).Caption
$info["hostname"] = $env:COMPUTERNAME

# Python
try {
    $pyVer = & python --version 2>&1
    $info["python"] = "$pyVer"
    $info["python_path"] = (Get-Command python -ErrorAction SilentlyContinue).Source
} catch {
    $info["python"] = "NOT_FOUND"
}

# Npcap
if (Test-Path "C:\Program Files\Npcap\npcap.sys") {
    $info["npcap"] = "INSTALLED"
} else {
    $info["npcap"] = "NOT_FOUND"
}

# DFI directory
if (Test-Path "C:\Program Files\DFI") {
    $info["dfi_dir"] = "EXISTS"
    $info["dfi_contents"] = (Get-ChildItem "C:\Program Files\DFI" -Recurse -Name | Out-String).Trim()
} else {
    $info["dfi_dir"] = "NOT_FOUND"
}

# NSSM
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssm) {
    $info["nssm"] = $nssm.Source
} else {
    $info["nssm"] = "NOT_FOUND"
}

# Existing services
$svcs = Get-Service | Where-Object { $_.Name -like "*hunt*" -or $_.Name -like "*mesh*" -or $_.Name -like "*dfi*" -or $_.Name -like "*nssm*" }
if ($svcs) {
    $info["services"] = ($svcs | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join "; "
} else {
    $info["services"] = "NONE"
}

# Disk space
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$info["disk_free_gb"] = [math]::Round($disk.FreeSpace / 1GB, 1)

# Network adapters
$adapters = Get-NetAdapter | Where-Object Status -eq "Up" | ForEach-Object { "$($_.Name): $((Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress)" }
$info["adapters"] = ($adapters -join "; ")

# Firewall status
$fw = Get-NetFirewallProfile | ForEach-Object { "$($_.Name)=$($_.Enabled)" }
$info["firewall"] = ($fw -join "; ")

# Output
foreach ($k in $info.Keys | Sort-Object) {
    Write-Output "$k`: $($info[$k])"
}
