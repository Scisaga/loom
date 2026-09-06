param(
    [Parameter(Mandatory=$true)][ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,5}$')][string]$Version,
    [string]$Wix = 'wix.exe',
    [string]$OutputDirectory,
    [string]$CertificateThumbprint = $env:LOOM_WINDOWS_SIGN_CERT,
    [string]$TimestampUrl = $env:LOOM_WINDOWS_TIMESTAMP_URL,
    [string]$SignTool = 'signtool.exe',
    [switch]$RequireSigned
)
$ErrorActionPreference = 'Stop'
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot '..\out' }
$output = (Resolve-Path -LiteralPath $OutputDirectory).Path
$source = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\clients\windows\installer\Package.wxs')).Path
if ($RequireSigned -and (-not $CertificateThumbprint -or -not $TimestampUrl)) {
    throw 'Signed release requires LOOM_WINDOWS_SIGN_CERT and LOOM_WINDOWS_TIMESTAMP_URL.'
}
if ([bool]$CertificateThumbprint -ne [bool]$TimestampUrl) { throw 'Specify both signing certificate and timestamp URL.' }
$lock = [IO.File]::Open((Join-Path $output '.windows-installer.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
$stage = Join-Path $output ('.windows-msi-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stage | Out-Null
try {
    # 六包清单是输入提交标记；先完整校验，再构建，最后发布两份 MSI 与清单。
    $hashes = @{}
    foreach ($line in Get-Content -LiteralPath (Join-Path $output 'windows-clients-SHA256SUMS')) {
        if ($line -notmatch '^([0-9a-f]{64})  (loom-client-windows-(?:installed|portable-mixed|portable-tun)-(?:amd64|arm64)\.zip)$') { throw 'Invalid ZIP manifest.' }
        $name = $Matches[2]
        if ($hashes.ContainsKey($name)) { throw 'Duplicate ZIP in manifest.' }
        $hashes[$name] = $Matches[1]
        if ((Get-FileHash -LiteralPath (Join-Path $output $name) -Algorithm SHA256).Hash -ne $hashes[$name]) { throw "ZIP hash mismatch: $name" }
    }
    if ($hashes.Count -ne 6) { throw 'The complete six-ZIP build is required.' }
    $manifest = @()
    foreach ($arch in @('amd64','arm64')) {
        $name = "loom-client-windows-installed-$arch"
        $bundle = Join-Path $stage $arch
        $zip = Join-Path $stage "$name.zip"
        Copy-Item -LiteralPath (Join-Path $output "$name.zip") -Destination $zip
        if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne $hashes["$name.zip"]) { throw 'Input ZIP changed during staging.' }
        Expand-Archive -LiteralPath $zip -DestinationPath $bundle
        Move-Item -LiteralPath (Join-Path $bundle "$name.exe") -Destination (Join-Path $bundle 'loom-client.exe')
        if ($CertificateThumbprint) {
            & (Join-Path $PSScriptRoot 'sign-windows-artifact.ps1') -Path (Join-Path $bundle 'loom-client.exe') -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl -SignTool $SignTool
        }
        $wixArch = if ($arch -eq 'amd64') { 'x64' } else { 'arm64' }
        $msi = Join-Path $stage "$name.msi"
        $wixArgs = @('build', ('"' + $source + '"'), '-arch', $wixArch, '-d', "Version=$Version", '-d', ('"SourceDir=' + $bundle + '"'), '-intermediateFolder', ('"' + (Join-Path $stage "obj-$arch") + '"'), '-o', ('"' + $msi + '"'))
        $process = Start-Process -FilePath $Wix -ArgumentList $wixArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $stage 'wix.log') -RedirectStandardError (Join-Path $stage 'wix.err')
        Get-Content -LiteralPath (Join-Path $stage 'wix.log'),(Join-Path $stage 'wix.err')
        if ($process.ExitCode -ne 0) { throw "WiX build failed: $arch" }
        if ($CertificateThumbprint) {
            & (Join-Path $PSScriptRoot 'sign-windows-artifact.ps1') -Path $msi -CertificateThumbprint $CertificateThumbprint -TimestampUrl $TimestampUrl -SignTool $SignTool
        }
        $manifest += (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() + "  $name.msi"
    }
    [IO.File]::WriteAllLines((Join-Path $stage 'windows-installers-SHA256SUMS'), $manifest, [Text.Encoding]::ASCII)
    foreach ($arch in @('amd64','arm64')) {
        Move-Item -LiteralPath (Join-Path $stage "loom-client-windows-installed-$arch.msi") -Destination $output -Force
    }
    Move-Item -LiteralPath (Join-Path $stage 'windows-installers-SHA256SUMS') -Destination $output -Force
} finally {
    Remove-Item -LiteralPath $stage -Recurse -Force
    $lock.Dispose()
}
