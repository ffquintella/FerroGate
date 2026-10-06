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

# 1b. The status group (feature F18): members may read the agent's read-only
#     status endpoint (the mia-tray companion, `mia status`); the daemon grants
#     it on the status pipe DACL (status.group, default FerroGateStatus), so it
#     must exist before the service starts. The installing user is added when
#     it is a real account (not SYSTEM / a machine account, as under SCCM);
#     the membership applies from that user's next logon.
Write-Host 'Ensuring the FerroGateStatus local group exists...'
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & $netExe localgroup FerroGateStatus *> $null
    if ($LASTEXITCODE -ne 0) {
        & $netExe localgroup FerroGateStatus /add /comment:"FerroGate MIA status readers (mia-tray)" *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create the FerroGateStatus local group (net.exe exit code $LASTEXITCODE)."
        }
        Write-Host 'Created local group FerroGateStatus.'
    }
    $installer = $env:USERNAME
    if ($installer -and $installer -ne 'SYSTEM' -and -not $installer.EndsWith('$')) {
        $member = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$installer" } else { $installer }
        & $netExe localgroup FerroGateStatus $member /add *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Added $member to FerroGateStatus (applies from the next logon)."
        }
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

# 3b. Make %ProgramData%\FerroGate administrator-only. The LocalSystem service
#     trusts what it finds there (configuration, environments.toml, allowlist
#     body and key, its machine key) and writes its log below it; left to
#     inherit %ProgramData%'s DACL, BUILTIN\Users could plant files or a `logs`
#     junction there and read the machine key. The service does this itself at
#     every start; running the same code here (mia::system_dir::prepare) makes
#     the install fail loudly instead. It creates the directory with the final
#     descriptor in one step (owner Administrators, protected DACL granting only
#     SYSTEM and Administrators), or locks an existing one through a handle that
#     never follows a junction, then refuses any reparse point below it and locks
#     every subdirectory that is not administrator-only.
$miaExe = Join-Path $installDir 'mia.exe'
Write-Host 'Securing the MIA configuration directory...'
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & $miaExe service secure-config
    if ($LASTEXITCODE -ne 0) {
        throw "mia.exe service secure-config failed with exit code $LASTEXITCODE; $env:ProgramData\FerroGate is not administrator-only."
    }
} finally {
    $ErrorActionPreference = $prevEap
}
$configDir = Join-Path $env:ProgramData 'FerroGate'
$icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'

# 3c. Files already in the directory keep their owners; the service refuses
#     any that SYSTEM or Administrators do not own. On Windows clients a file an
#     elevated administrator wrote (e.g. `mia setup` with an older release) is
#     owned by that administrator's own account: hand those — owner a direct
#     member of the local Administrators group — to the group and reset their
#     ACL to the directory's. Anything else was created by a non-administrator:
#     it is listed, never adopted. Review and delete it. `secure-config` has
#     already refused any reparse point below the directory, so nothing here is
#     reached through a link.
$trustedOwners = @('S-1-5-18', 'S-1-5-32-544')
$adminSids = @()
try {
    $adminSids = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.SID.Value })
} catch {
    Write-Warning "Could not list the local Administrators group ($($_.Exception.Message)); existing files are not adopted."
}
Get-ChildItem -LiteralPath $configDir -Recurse -Force -File -Attributes !ReparsePoint -ErrorAction SilentlyContinue | ForEach-Object {
    $path = $_.FullName
    try {
        $owner = (Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    } catch {
        Write-Warning "Could not read the owner of ${path}: $($_.Exception.Message). The mia service will refuse it until it is fixed."
        return
    }
    if ($trustedOwners -contains $owner) { return }
    # A file with several names shares its owner and DACL with a file
    # elsewhere: never adopt it (the service refuses it anyway).
    # (Stderr is not redirected under ErrorActionPreference=Stop; see step 1.)
    $fsutil = Join-Path $env:SystemRoot 'System32\fsutil.exe'
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $names = @(& $fsutil hardlink list $path)
    } finally {
        $ErrorActionPreference = $prevEap
    }
    if ($names.Count -gt 1) {
        Write-Warning "$path has $($names.Count) hard links: the mia service will refuse it. Delete it and write the file again."
        return
    }
    if ($adminSids -contains $owner) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $icacls $path /setowner '*S-1-5-32-544' *> $null
            $adopted = $LASTEXITCODE -eq 0
            if ($adopted) {
                & $icacls $path /reset *> $null
                $adopted = $LASTEXITCODE -eq 0
            }
        } finally {
            $ErrorActionPreference = $prevEap
        }
        if ($adopted) {
            Write-Host "Handed $path (owned by administrator $owner) to Administrators."
        } else {
            Write-Warning "Could not hand $path to Administrators; the mia service will refuse it."
        }
    } else {
        Write-Warning "$path is owned by $owner, not SYSTEM or Administrators: the mia service will refuse it. Delete it unless you know where it came from (to keep it: icacls `"$path`" /setowner *S-1-5-32-544 and icacls `"$path`" /reset)."
    }
}

# 4. Verify the MSI actually registered the service, and repair if it did not.
#    ServiceInstall in the MSI is non-vital, so Windows Installer can report
#    success while CreateService failed (e.g. a stale service still marked for
#    deletion). mia.exe ships its own registration (`mia service install`,
#    identical parameters), so use it as the authoritative fallback.
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
