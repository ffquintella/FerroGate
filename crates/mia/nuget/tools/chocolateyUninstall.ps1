$ErrorActionPreference = 'Stop'

# 1. Remove the product via msiexec /x. The MSI's uninstall sequence stops and
#    deregisters the mia Windows service before its files are removed.
$keys = @(Get-UninstallRegistryKey -SoftwareName 'FerroGate Machine Identity Agent*')

if ($keys.Count -eq 0) {
    Write-Warning 'FerroGate MIA was not found in the registry; skipping MSI removal.'
} elseif ($keys.Count -gt 1) {
    Write-Warning "Found $($keys.Count) matching entries; not removing automatically. Uninstall FerroGate MIA from 'Apps & features'."
} else {
    $productCode = $keys[0].PSChildName
    Write-Host "Uninstalling FerroGate MIA ($productCode)..."
    $exit = (Start-Process 'msiexec.exe' -ArgumentList "/x `"$productCode`" /qn /norestart" -Wait -PassThru -NoNewWindow).ExitCode
    if (@(0, 3010, 1641) -notcontains $exit) {
        throw "msiexec /x failed with exit code $exit"
    }
}

# 2. Drop the helper-API client group the installer created (mirrors NSIS).
#    Non-fatal if it is already gone. Stderr must not be redirected under
#    ErrorActionPreference=Stop (it becomes a terminating error), so relax
#    the preference around the net.exe call.
Write-Host 'Removing the FerroGateClients local group...'
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & (Join-Path $env:SystemRoot 'System32\net.exe') localgroup FerroGateClients /delete *> $null
} finally {
    $ErrorActionPreference = $prevEap
}

# The PATH entry added via Install-ChocolateyPath is removed by Chocolatey
# automatically when the package is uninstalled.
