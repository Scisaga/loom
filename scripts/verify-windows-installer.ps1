param(
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$IconPath
)
$ErrorActionPreference = 'Stop'
if (-not $IconPath) { $IconPath = Join-Path $PSScriptRoot '..\clients\windows\favicon.ico' }
$msi = (Resolve-Path -LiteralPath $Path).Path
$icon = (Resolve-Path -LiteralPath $IconPath).Path
$msiName = [IO.Path]::GetFileName($msi)
if ($msiName -notmatch '^loom-client-windows-installed-(amd64|arm64)\.msi$') {
    throw 'Installer file name must bind one supported architecture.'
}
$expectedTemplate = if ($Matches[1] -eq 'amd64') { 'x64;1033' } else { 'Arm64;1033' }
$iconBytes = [IO.File]::ReadAllBytes($icon)
if ($iconBytes.Length -lt 6 -or [BitConverter]::ToUInt16($iconBytes, 0) -ne 0 -or
    [BitConverter]::ToUInt16($iconBytes, 2) -ne 1 -or [BitConverter]::ToUInt16($iconBytes, 4) -eq 0) {
    throw 'Installer icon must be the native ICO asset.'
}

# OpenDatabase mode 0 is read-only: validate the built artifact without
# installing it or affecting the running client, service, or retained identity.
$objects = [Collections.Generic.List[object]]::new()
try {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $objects.Add($installer)
    $summary = $installer.SummaryInformation($msi, 0)
    $objects.Add($summary)
    if ($summary.Property(7) -cne $expectedTemplate -or $summary.Property(14) -ne 500) {
        throw 'Installer Template/Page Count Summary does not match its architecture and schema.'
    }
    $database = $installer.OpenDatabase($msi, 0)
    $objects.Add($database)
    $view = $database.OpenView('SELECT `Name`, `Data` FROM `Icon`')
    $objects.Add($view)
    $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw 'Installer icon is missing.' }
    $objects.Add($record)
    if ($record.StringData(1) -ne 'LoomIcon' -or $record.DataSize(2) -ne $iconBytes.Length) {
        throw 'Installer icon has an unexpected name or size; do not embed the full EXE in the Icon table.'
    }
    # msiReadStreamBytes (1) returns exactly one byte per BSTR character.
    $stream = [string]$record.ReadStream(2, $iconBytes.Length, 1)
    $embedded = [Text.Encoding]::GetEncoding(28591).GetBytes($stream)
    if ([Convert]::ToBase64String($embedded) -cne [Convert]::ToBase64String($iconBytes)) {
        throw 'Installer icon differs from the canonical favicon ICO.'
    }
    $extra = $view.Fetch()
    if ($extra) {
        $objects.Add($extra)
        throw 'Installer contains unexpected extra icons.'
    }
    $view.Close()

    $view = $database.OpenView('SELECT `Value` FROM `Property` WHERE `Property` = ''ARPPRODUCTICON''')
    $objects.Add($view)
    $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw 'Uninstall icon reference is missing.' }
    $objects.Add($record)
    if ($record.StringData(1) -ne 'LoomIcon') { throw 'Uninstall entry must use the verified favicon.' }
    $view.Close()

    $view = $database.OpenView('SELECT `Icon_`, `Target` FROM `Shortcut` WHERE `Shortcut` = ''LoomShortcut''')
    $objects.Add($view)
    $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw 'Client shortcut is missing.' }
    $objects.Add($record)
    if ($record.StringData(1) -ne 'LoomIcon' -or $record.StringData(2) -ne '[#ClientExe]') {
        throw 'Client shortcut must target the client executable and use the verified favicon.'
    }
    $view.Close()

    $view = $database.OpenView('SELECT `FileName` FROM `File`')
    $objects.Add($view)
    $view.Execute()
    $actualFiles = @()
    while ($record = $view.Fetch()) {
        $objects.Add($record)
        $name = $record.StringData(1)
        $separator = $name.IndexOf('|')
        if ($separator -ge 0) { $name = $name.Substring($separator + 1) }
        $actualFiles += $name
    }
    $view.Close()
    $expectedFiles = @(
        'loom-client.exe', 'windows-dataplane.zip', 'PREVIEW-NOTICE.txt', 'LICENSE', 'NOTICE',
        'gozxing-LICENSE', 'golang-x-net-LICENSE', 'golang-x-net-PATENTS',
        'golang-x-sys-LICENSE', 'golang-x-sys-PATENTS',
        'golang-x-text-LICENSE', 'golang-x-text-PATENTS',
        'golang-x-xerrors-LICENSE', 'golang-x-xerrors-PATENTS', 'yaml-v3-LICENSE'
    )
    if ($actualFiles.Count -ne $expectedFiles.Count -or
        @(Compare-Object $actualFiles $expectedFiles).Count -ne 0) {
        throw 'Installer file table does not contain the exact client, data plane, notices, and licenses.'
    }

    $view = $database.OpenView('SELECT `ServiceInstall`,`Name`,`ServiceType`,`StartType`,`ErrorControl`,`StartName`,`Component_` FROM `ServiceInstall`')
    $objects.Add($view)
    $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw 'Loom service installation is missing.' }
    $objects.Add($record)
    if ($record.StringData(1) -ne 'Service' -or $record.StringData(2) -ne 'LoomClient' -or
        $record.IntegerData(3) -ne 16 -or $record.IntegerData(4) -ne 2 -or
        $record.IntegerData(5) -ne 32769 -or $record.StringData(6) -ne 'LocalSystem' -or
        $record.StringData(7) -ne 'Client') {
        throw 'Loom service must be a vital, automatic, own-process LocalSystem service tied to Client.'
    }
    if ($view.Fetch()) { throw 'Installer contains an unexpected additional service.' }
    $view.Close()

    $view = $database.OpenView('SELECT `ServiceControl`,`Name`,`Event`,`Component_` FROM `ServiceControl`')
    $objects.Add($view)
    $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw 'Loom service lifecycle control is missing.' }
    $objects.Add($record)
    if ($record.StringData(1) -ne 'ServiceControl' -or $record.StringData(2) -ne 'LoomClient' -or
        $record.IntegerData(3) -ne 163 -or $record.StringData(4) -ne 'Client') {
        throw 'Loom service must start on install and stop/delete on uninstall.'
    }
    if ($view.Fetch()) { throw 'Installer contains unexpected additional service control.' }
    $view.Close()

    $view = $database.OpenView('SELECT `Directory_`,`Component_` FROM `CreateFolder`')
    $objects.Add($view)
    $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw 'Protected machine state folder is missing.' }
    $objects.Add($record)
    if ($record.StringData(1) -ne 'StateFolder' -or $record.StringData(2) -ne 'MachineState') {
        throw 'Machine state folder is not owned by the permanent MachineState component.'
    }
    if ($view.Fetch()) { throw 'Installer contains an unexpected additional CreateFolder row.' }
    $view.Close()

    $view = $database.OpenView('SELECT `LockObject`,`Table`,`SDDLText`,`Condition` FROM `MsiLockPermissionsEx`')
    $objects.Add($view)
    $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw 'Machine state ACL is missing.' }
    $objects.Add($record)
    $expectedSDDL = 'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if ($record.StringData(1) -ne 'StateFolder' -or $record.StringData(2) -ne 'CreateFolder' -or
        $record.StringData(3) -cne $expectedSDDL -or $record.StringData(4) -ne '') {
        throw 'Machine state ACL must grant inherited full access only to SYSTEM and Administrators.'
    }
    if ($view.Fetch()) { throw 'Installer contains an unexpected additional ACL row.' }
    $view.Close()

    $view = $database.OpenView('SELECT `Root`,`Key`,`Name`,`Value`,`Component_` FROM `Registry` WHERE `Name` = ''OperatorSID''')
    $objects.Add($view)
    $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw 'Installed operator SID binding is missing.' }
    $objects.Add($record)
    if ($record.IntegerData(1) -ne 2 -or $record.StringData(2) -ne 'SOFTWARE\Loom' -or
        $record.StringData(3) -ne 'OperatorSID' -or $record.StringData(4) -ne '[LOOM_OPERATOR_SID]' -or
        $record.StringData(5) -ne 'MachineState') {
        throw 'Installed operator SID must be machine-scoped and owned by MachineState.'
    }
    if ($view.Fetch()) { throw 'Installer contains duplicate operator SID bindings.' }
    $view.Close()

    Write-Output "Verified MSI architecture, exact files, service lifecycle, state ACL, operator binding, favicon, and shortcut: $msi"
} finally {
    for ($index = $objects.Count - 1; $index -ge 0; $index--) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($objects[$index])
    }
}
