$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

Write-Output "=== Python ==="
try { python --version } catch { Write-Output "NOT FOUND" }

Write-Output "=== NSSM ==="
if (Test-Path "C:\Windows\System32\nssm.exe") {
    Write-Output "INSTALLED at C:\Windows\System32\nssm.exe"
} else {
    Write-Output "NOT FOUND"
}

Write-Output "=== Npcap ==="
if (Test-Path "C:\Program Files\Npcap\npcap.sys") {
    Write-Output "INSTALLED"
} else {
    Write-Output "NOT FOUND"
}

Write-Output "=== DFI Dir ==="
if (Test-Path "C:\Program Files\DFI") {
    Get-ChildItem "C:\Program Files\DFI" -Name
} else {
    Write-Output "NOT FOUND"
}

Write-Output "=== Temp files ==="
Get-ChildItem $env:TEMP -Name -Filter "npcap*" -ErrorAction SilentlyContinue
Get-ChildItem $env:TEMP -Name -Filter "nssm*" -ErrorAction SilentlyContinue
Get-ChildItem $env:TEMP -Name -Filter "python*" -ErrorAction SilentlyContinue
