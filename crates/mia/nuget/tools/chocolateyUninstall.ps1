$ErrorActionPreference = 'Stop'

# Find the installed product in the uninstall registry and remove it with
# msiexec /x. The MSI's own uninstall sequence stops + deregisters the mia
# service and drops the FerroGateClients group.
$keys = @(Get-UninstallRegistryKey -SoftwareName 'FerroGate Machine Identity Agent*')

if ($keys.Count -eq 0) {
    Write-Warning 'FerroGate MIA was not found in the registry; nothing to uninstall.'
    return
}

if ($keys.Count -gt 1) {
    Write-Warning "Found $($keys.Count) matching entries; not uninstalling automatically. Remove FerroGate MIA from 'Apps & features'."
    return
}

$productCode = $keys[0].PSChildName
Write-Host "Uninstalling FerroGate MIA ($productCode)…"
$exit = (Start-Process 'msiexec.exe' -ArgumentList "/x `"$productCode`" /qn /norestart" -Wait -PassThru -NoNewWindow).ExitCode
if (@(0, 3010, 1641) -notcontains $exit) {
    throw "msiexec /x failed with exit code $exit"
}
