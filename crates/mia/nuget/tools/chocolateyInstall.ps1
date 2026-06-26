$ErrorActionPreference = 'Stop'

# Install the MSI bundled alongside this script. The MSI itself adds mia.exe to
# the system PATH, creates the FerroGateClients helper group, and registers +
# starts the mia Windows service (see crates/mia/wix/mia.wxs).
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

$packageArgs = @{
    packageName    = 'ferrogate-mia'
    fileType       = 'msi'
    file           = Join-Path $toolsDir 'ferrogate-mia.msi'
    silentArgs     = '/qn /norestart'
    validExitCodes = @(0, 3010, 1641)
}

Install-ChocolateyInstallPackage @packageArgs
