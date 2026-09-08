param(
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$IconPath
)
$ErrorActionPreference = 'Stop'
if (-not $IconPath) { $IconPath = Join-Path $PSScriptRoot '..\clients\windows\favicon.ico' }
$msi = (Resolve-Path -LiteralPath $Path).Path
$icon = (Resolve-Path -LiteralPath $IconPath).Path
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
    Write-Output "Verified MSI favicon ($($iconBytes.Length) bytes), uninstall entry, and client shortcut: $msi"
} finally {
    for ($index = $objects.Count - 1; $index -ge 0; $index--) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($objects[$index])
    }
}
