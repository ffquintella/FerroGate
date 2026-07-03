$ErrorActionPreference = 'Stop'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$installDir = Join-Path $env:ProgramFiles 'FerroGate\MIA'

# 1. Create the local group that guards the helper pipe BEFORE installing, so
#    the service (started by the MSI) finds it when it binds the named pipe.
#    The default config (helper.windows_group = "FerroGateClients") restricts the
#    pipe DACL to this group; without it the daemon cannot resolve the SID. Add
#    vetted client accounts to this group so they may request tokens.
#    net.exe is referenced by absolute path: config-management agents (Puppet,
#    SCCM) run choco with a minimal PATH that may not contain System32.
#    NOTE: do NOT redirect net.exe stderr (2>&1) here - under
#    ErrorActionPreference=Stop that turns stderr output (e.g. system error
#    1379, "group already exists") into a terminating error. Instead, probe
#    for the group first and only create it when missing.
$netExe = Join-Path $env:SystemRoot 'System32\net.exe'
Write-Host 'Ensuring the FerroGateClients local group exists...'
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & $netExe localgroup FerroGateClients *> $null
    if ($LASTEXITCODE -ne 0) {
        & $netExe localgroup FerroGateClients /add /comment:"FerroGate MIA helper-API clients" *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create the FerroGateClients local group (net.exe exit code $LASTEXITCODE)."
        }
        Write-Host 'Created local group FerroGateClients.'
    } else {
        Write-Host 'Local group FerroGateClients already exists.'
    }
} finally {
    $ErrorActionPreference = $prevEap
}

# 2. Add the install dir to the system PATH (Chocolatey records it for clean
#    removal on uninstall).
Install-ChocolateyPath -PathToInstall $installDir -PathType 'Machine'

# 3. Install the bundled MSI. The MSI lays down mia.exe and registers + starts
#    the mia Windows service.
$packageArgs = @{
    packageName    = 'ferrogate-mia'
    fileType       = 'msi'
    file           = Join-Path $toolsDir 'ferrogate-mia.msi'
    silentArgs     = '/qn /norestart'
    validExitCodes = @(0, 3010, 1641)
}
Install-ChocolateyInstallPackage @packageArgs
