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
#    the mia Windows service. Keep a verbose msiexec log next to Chocolatey's
#    own logs: the MSI declares the service non-vital (a bare-MSI install must
#    not hard-fail on service quirks), so this log is the only record of a
#    failed InstallServices/StartServices action.
$msiLog = Join-Path $env:ProgramData 'chocolatey\logs\ferrogate-mia.msi.install.log'
$packageArgs = @{
    packageName    = 'ferrogate-mia'
    fileType       = 'msi'
    file           = Join-Path $toolsDir 'ferrogate-mia.msi'
    silentArgs     = "/qn /norestart /l*v `"$msiLog`""
    validExitCodes = @(0, 3010, 1641)
}
Install-ChocolateyInstallPackage @packageArgs

# 4. Verify the MSI actually registered the service, and repair if it did not.
#    ServiceInstall in the MSI is non-vital, so Windows Installer can report
#    success while CreateService failed (e.g. a stale service still marked for
#    deletion). mia.exe ships its own registration (`mia service install`,
#    identical parameters), so use it as the authoritative fallback.
$miaExe = Join-Path $installDir 'mia.exe'
if (-not (Get-Service -Name 'mia' -ErrorAction SilentlyContinue)) {
    Write-Warning "The MSI did not register the 'mia' service (see $msiLog); registering it via mia.exe..."
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $miaExe service install
        if ($LASTEXITCODE -ne 0) {
            throw "mia.exe service install failed with exit code $LASTEXITCODE."
        }
    } finally {
        $ErrorActionPreference = $prevEap
    }
}

# 5. Make sure the service is running (the MSI's StartServices is fire-and-
#    forget). A start failure is a warning, not an error: on first install the
#    config (mia.env / mia.toml) is typically laid down by the config-management
#    agent right after this package, which then ensures the service is running.
$svc = Get-Service -Name 'mia' -ErrorAction SilentlyContinue
if (-not $svc) {
    throw "The 'mia' service is still not registered after the fallback; see $msiLog."
}
if ($svc.Status -ne 'Running') {
    try {
        Start-Service -Name 'mia' -ErrorAction Stop
        Write-Host "Started the 'mia' service."
    } catch {
        Write-Warning "The 'mia' service is registered but could not be started yet: $($_.Exception.Message)"
    }
} else {
    Write-Host "The 'mia' service is registered and running."
}
