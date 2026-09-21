$ErrorActionPreference = 'Stop'

$runRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$test = Join-Path $runRoot 'loom-windows-tests.exe'
$evidence = Join-Path $runRoot 'evidence'
$result = Join-Path $runRoot 'interactive-exit-code.txt'
New-Item -ItemType Directory -Force -Path $evidence | Out-Null

try {
    & $test '-test.v' *>&1 | Tee-Object -FilePath (Join-Path $evidence 'windows-tests.txt')
    $code = $LASTEXITCODE
} catch {
    $_ | Out-String | Set-Content -LiteralPath (Join-Path $evidence 'windows-tests-error.txt') -Encoding utf8
    $code = 1
}
[IO.File]::WriteAllText($result, [string]$code, [Text.Encoding]::ASCII)
if ($code -ne 0) {
    throw "Windows test binary failed with exit code $code."
}
