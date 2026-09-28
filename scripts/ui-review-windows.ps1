$ErrorActionPreference = 'Stop'

$runRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$evidenceRoot = Join-Path $runRoot 'evidence\windows'
$captureRoot = Join-Path $evidenceRoot 'current'
Remove-Item -LiteralPath $evidenceRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $captureRoot | Out-Null

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LoomUIReviewDpi {
    [DllImport("user32.dll")]
    public static extern uint GetDpiForSystem();
}
'@
$dpi = [LoomUIReviewDpi]::GetDpiForSystem()
if ($dpi -ne 96) {
    throw "Windows UI review requires 96 DPI; current DPI is $dpi."
}

$test = Join-Path $runRoot 'windows-renderer.test.exe'
if (-not (Test-Path -LiteralPath $test -PathType Leaf)) {
    throw 'Windows UI review test executable is missing.'
}
$env:LOOM_UI_CAPTURE_DIR = $captureRoot
& $test '-test.run=^TestGUIVisualScenarios$' '-test.v'
if ($LASTEXITCODE -ne 0) {
    throw "Windows UI review tests failed with exit code $LASTEXITCODE."
}

$images = @(Get-ChildItem -LiteralPath $captureRoot -Filter '*.png' -File)
if ($images.Count -ne 8) {
    throw "Windows UI review produced $($images.Count) images; expected 8."
}
$metadata = @(
    '{'
    '  "renderer": "Win32 Direct2D/DirectWrite WM_PRINT",'
    '  "renderer_version": "portable-gui-wm-print-v1",'
    '  "viewport": "876x614px",'
    ('  "dpi": "' + $dpi + '",')
    ('  "os_build": "' + [Environment]::OSVersion.Version.ToString() + '"')
    '}'
) -join "`n"
# Emit the same LF/UTF-8 bytes on every Windows PowerShell version.
$utf8 = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $evidenceRoot 'metadata.json'), $metadata + "`n", $utf8)
