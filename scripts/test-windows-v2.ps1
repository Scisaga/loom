param(
    [string]$RepositoryRoot,
    [string]$OutputDirectory,
    [string]$PlatformPublicKey,
    [string]$EvidencePath,
    [string]$ProfileRoot,
    [string]$InstalledInviteCarrier,
    [string]$InstalledResumeCarrier,
    [switch]$RunInstalledLifecycle,
    [switch]$RunPortableMixedLifecycle,
    [switch]$RunPortableTUNLifecycle,
    [ValidateSet('user', 'machine')][string]$TombstoneScope,
    [string]$MultiProfileEvidencePath,
    [string]$UnderlayEvidencePath,
    [switch]$RequirePackages,
    [switch]$RequireMSI,
    [switch]$RequireAuthenticode
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($env:OS -ne 'Windows_NT') { throw 'Windows v2 native acceptance must run on Windows.' }
if (-not $RepositoryRoot) { $RepositoryRoot = Join-Path $PSScriptRoot '..' }
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$hostArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
if ($hostArchitecture -eq 'x64') { $hostArchitecture = 'amd64' }
if ($hostArchitecture -ne 'amd64' -and $hostArchitecture -ne 'arm64') {
    throw "Unsupported Windows architecture: $hostArchitecture"
}
if (-not $EvidencePath) {
    $EvidencePath = Join-Path $root "out\windows-v2-host-$hostArchitecture.json"
}
$evidenceParent = Split-Path -Parent $EvidencePath
if (-not $evidenceParent) { throw 'EvidencePath must include a parent directory.' }
New-Item -ItemType Directory -Path $evidenceParent -Force | Out-Null

$checks = [ordered]@{
    repository_safety = $null
    native_go_tests = $null
    native_v2_verifier = $null
    native_go_vet = $null
    native_dpapi_cng = $null
    cross_compile_amd64 = $null
    cross_compile_arm64 = $null
    native_package_build_info = $null
    six_zip_manifest = $null
    zip_exact_contents = $null
    dataplane_signatures = $null
    two_msi_manifest = $null
    msi_database = $null
    authenticode = $null
    installed_ui_join = $null
    installed_resume = $null
    installed_lifecycle = $null
    portable_mixed_lifecycle = $null
    portable_tun_lifecycle = $null
    tombstone_cleanup_user = $null
    tombstone_cleanup_machine = $null
    multi_profile_ui = $null
    underlay_generation_change = $null
}
$activeCheck = 'initialization'
$failure = $null
$completed = $false
$evidenceArtifacts = [ordered]@{}
$commit = ''
$sourceClean = $false
$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('loom-windows-v2-' + [Guid]::NewGuid().ToString('N'))
$locationPushed = $false

function Invoke-Checked {
    param([string]$Name, [string]$FilePath, [string[]]$ArgumentList)
    $script:activeCheck = $Name
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
}

function Get-PEMachine {
    param([string]$Path)
    $stream = [IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        $reader = [IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Missing PE DOS signature.' }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0x40 -or $peOffset -gt $stream.Length - 24) { throw 'Invalid PE header offset.' }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw 'Missing PE signature.' }
        return $reader.ReadUInt16()
    } finally {
        $stream.Dispose()
    }
}

function Export-ZipEntry {
    param($Archive, [string]$Name, [string]$Destination)
    $entry = $Archive.GetEntry($Name)
    if ($null -eq $entry) { throw "ZIP entry is missing: $Name" }
    $source = $entry.Open()
    $target = [IO.File]::Open($Destination, 'CreateNew', 'Write', 'None')
    try { $source.CopyTo($target) } finally { $target.Dispose(); $source.Dispose() }
}

function Read-ClientBuildInfo {
    param([string]$Path, [string]$Name)
    $stdout = Join-Path $temporaryRoot "$Name-build-info.json"
    $stderr = Join-Path $temporaryRoot "$Name-build-info.err"
    $process = Start-Process -FilePath $Path -ArgumentList '--build-info' -Wait -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    if ($process.ExitCode -ne 0) { throw "Cannot read build info: $Name.exe" }
    $text = (Get-Content -LiteralPath $stdout -Raw).Trim()
    if (-not $text) { throw "Cannot read build info: $Name.exe" }
    return ($text | ConvertFrom-Json)
}

function Read-ChecksumManifest {
    param([string]$Path, [string]$Pattern, [int]$ExpectedCount)
    $entries = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ($line -notmatch $Pattern) { throw "Invalid checksum manifest line in $([IO.Path]::GetFileName($Path))." }
        $digest = $Matches[1]
        $name = $Matches[2]
        if ($entries.ContainsKey($name)) { throw "Duplicate checksum entry: $name" }
        $entries[$name] = $digest
    }
    if ($entries.Count -ne $ExpectedCount) { throw "Incomplete checksum manifest: $([IO.Path]::GetFileName($Path))." }
    foreach ($name in $entries.Keys) {
        $path = Join-Path (Split-Path -Parent $Path) $name
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -cne $entries[$name]) { throw "Checksum mismatch: $name" }
    }
    return $entries
}

function Test-AuthenticodeFile {
    param([string]$Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
        $null -eq $signature.TimeStamperCertificate) {
        throw "Trusted Authenticode signature and timestamp required: $([IO.Path]::GetFileName($Path))"
    }
}

function Add-EvidenceArtifact {
    param([string]$Name, [string]$Path)
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -lt 1 -or $item.Length -gt 64MB -or $item.FullName.StartsWith('\\')) {
        throw "$Name evidence must be a bounded local regular file."
    }
    $script:evidenceArtifacts[$Name] = [ordered]@{
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        size_bytes = $item.Length
    }
}

try {
    Push-Location $root
    $locationPushed = $true
    if ($InstalledInviteCarrier -and $InstalledResumeCarrier) {
        throw 'Invite completion and committed resume require separate clean-state evidence runs.'
    }
    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    $activeCheck = 'source_coordinate'
    $commit = (& git -C $root rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Cannot resolve source commit.' }
    $porcelain = @(& git -C $root status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect source worktree.' }
    $sourceClean = $porcelain.Count -eq 0

    $python = Get-Command python3 -ErrorAction SilentlyContinue
    $pythonArguments = @((Join-Path $root 'scripts\check_repository_safety.py'))
    if ($null -eq $python) {
        $python = Get-Command py -ErrorAction SilentlyContinue
        $pythonArguments = @('-3', (Join-Path $root 'scripts\check_repository_safety.py'))
    }
    if ($null -eq $python) { throw 'python3 or py -3 is required for the repository safety check.' }
    Invoke-Checked 'repository_safety' $python.Source $pythonArguments
    $checks.repository_safety = $true

    $nativePackages = @(
        './clients/windows', './internal/clientruntime', './internal/clientsecret',
        './internal/clientjoin', './internal/clientreport', './internal/clientv2',
        './internal/windowsv2', './internal/wire'
    )
    $crossCompilePackages = $nativePackages + @('./internal/enrollmentv2')
    Invoke-Checked 'native_go_tests' 'go' (@('test', '-count=1', '-vet=off') + $nativePackages)
    $checks.native_go_tests = $true
    Invoke-Checked 'native_v2_verifier' 'go' @(
        'test', '-count=1', '-vet=off', './internal/enrollmentv2',
        '-run', '^(TestCoordinator|TestEnrollment|TestApprovalVoter)'
    )
    $checks.native_v2_verifier = $true
    Invoke-Checked 'native_go_vet' 'go' (@('vet', '-unsafeptr=false') + $crossCompilePackages)
    $checks.native_go_vet = $true
    Invoke-Checked 'native_dpapi_cng' 'go' @(
        'test', '-count=1', '-vet=off', './internal/windowsv2',
        '-run', '^TestNativeDPAPIDescriptorUsesNonExportableCNGIdentity$'
    )
    $checks.native_dpapi_cng = $true

    $oldGOOS = $env:GOOS
    $oldGOARCH = $env:GOARCH
    $oldCGO = $env:CGO_ENABLED
    try {
        $env:GOOS = 'windows'
        $env:CGO_ENABLED = '0'
        foreach ($architecture in @('amd64', 'arm64')) {
            $activeCheck = "cross_compile_$architecture"
            $env:GOARCH = $architecture
            $index = 0
            foreach ($package in $crossCompilePackages) {
                $target = Join-Path $temporaryRoot ("compile-$architecture-$index.test.exe")
                & go test -c -vet=off -o $target $package
                if ($LASTEXITCODE -ne 0) { throw "$activeCheck failed for $package" }
                $index++
            }
            $checks["cross_compile_$architecture"] = $true
        }
    } finally {
        $env:GOOS = $oldGOOS
        $env:GOARCH = $oldGOARCH
        $env:CGO_ENABLED = $oldCGO
    }

    if ($OutputDirectory) {
        $output = (Resolve-Path -LiteralPath $OutputDirectory).Path
        if (-not $PlatformPublicKey) { throw 'PlatformPublicKey is required when package verification is enabled.' }
        $publicKey = (Resolve-Path -LiteralPath $PlatformPublicKey).Path
        $activeCheck = 'six_zip_manifest'
        $zipManifest = Read-ChecksumManifest (Join-Path $output 'windows-clients-SHA256SUMS') `
            '^([0-9a-f]{64})  (loom-client-windows-(?:installed|portable-mixed|portable-tun)-(?:amd64|arm64)\.zip)$' 6
        $checks.six_zip_manifest = $true
        Add-Type -AssemblyName ('System.' + 'IO.Compression.FileSystem')
        $componentHashes = @{}
        foreach ($architecture in @('amd64', 'arm64')) {
            foreach ($edition in @('installed', 'portable-mixed', 'portable-tun')) {
                $base = "loom-client-windows-$edition-$architecture"
                $zipPath = Join-Path $output "$base.zip"
                $archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
                try {
                    $expected = @(
                        "$base.exe", 'windows-dataplane.zip', 'PREVIEW-NOTICE.txt', 'LICENSE', 'NOTICE',
                        'licenses/gozxing-LICENSE', 'licenses/golang-x-net-LICENSE', 'licenses/golang-x-net-PATENTS',
                        'licenses/golang-x-sys-LICENSE', 'licenses/golang-x-sys-PATENTS',
                        'licenses/golang-x-text-LICENSE', 'licenses/golang-x-text-PATENTS',
                        'licenses/golang-x-xerrors-LICENSE', 'licenses/golang-x-xerrors-PATENTS',
                        'licenses/yaml-v3-LICENSE'
                    )
                    $actual = @($archive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
                    if ($actual.Count -ne $expected.Count -or @(Compare-Object $actual $expected).Count -ne 0) {
                        throw "ZIP member set is not exact: $base.zip"
                    }
                    $exePath = Join-Path $temporaryRoot "$base.exe"
                    $componentPath = Join-Path $temporaryRoot "component-$edition-$architecture.zip"
                    Export-ZipEntry $archive "$base.exe" $exePath
                    Export-ZipEntry $archive 'windows-dataplane.zip' $componentPath
                } finally {
                    $archive.Dispose()
                }
                $wantedMachine = if ($architecture -eq 'amd64') { 0x8664 } else { 0xaa64 }
                if ((Get-PEMachine $exePath) -ne $wantedMachine) { throw "PE architecture mismatch: $base.exe" }
                $componentHash = (Get-FileHash -LiteralPath $componentPath -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($componentHashes.ContainsKey($architecture) -and
                    $componentHashes[$architecture] -cne $componentHash) {
                    throw "Editions do not carry one exact signed component for $architecture."
                }
                $componentHashes[$architecture] = $componentHash
                if ($architecture -eq $hostArchitecture) {
                    $buildInfo = Read-ClientBuildInfo $exePath $base
                    $binaryHash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
                    if ($buildInfo.edition -cne $edition -or
                        $buildInfo.coordinate.platform -cne "windows/$architecture" -or
                        $buildInfo.coordinate.tag -cne "windows-$edition-$architecture" -or
                        $buildInfo.coordinate.commit -cne $commit -or $buildInfo.coordinate.dirty -eq $true -or
                        $buildInfo.coordinate.binary -cne $binaryHash) {
                        throw "Build coordinate mismatch: $base.exe"
                    }
                }
                if ($RequireAuthenticode) { Test-AuthenticodeFile $exePath }
            }
            $component = Join-Path $temporaryRoot "component-portable-tun-$architecture.zip"
            Invoke-Checked 'dataplane_signatures' 'go' @(
                'run', './cmd/loom', 'client', 'verify-windows', '-archive', $component,
                '-pubkey', $publicKey, '-arch', $architecture
            )
        }
        $checks.native_package_build_info = $true
        $checks.zip_exact_contents = $true
        $checks.dataplane_signatures = $true
        if ($RequireAuthenticode) { $checks.authenticode = $true }

        $msiManifestPath = Join-Path $output 'windows-installers-SHA256SUMS'
        if ((Test-Path -LiteralPath $msiManifestPath) -or $RequireMSI) {
            $activeCheck = 'two_msi_manifest'
            $null = Read-ChecksumManifest $msiManifestPath `
                '^([0-9a-f]{64})  (loom-client-windows-installed-(?:amd64|arm64)\.msi)$' 2
            $checks.two_msi_manifest = $true
            foreach ($architecture in @('amd64', 'arm64')) {
                $msi = Join-Path $output "loom-client-windows-installed-$architecture.msi"
                Invoke-Checked 'msi_database' 'powershell.exe' @(
                    '-NoProfile', '-NonInteractive', '-File', (Join-Path $root 'scripts\verify-windows-installer.ps1'),
                    '-Path', $msi
                )
                if ($RequireAuthenticode) { Test-AuthenticodeFile $msi }
            }
            $checks.msi_database = $true
        }
    } elseif ($RequirePackages -or $RequireMSI -or $RequireAuthenticode) {
        throw 'OutputDirectory is required by the selected package gates.'
    }

    $oldV2 = $env:LOOM_ACCEPT_WINDOWS_V2
    $oldProfileRoot = $env:LOOM_ACCEPT_V2_PROFILE_ROOT
    $oldInstalled = $env:LOOM_ACCEPT_INSTALLED
    $oldCarrier = $env:LOOM_ACCEPT_INSTALLED_QR
    $oldMixed = $env:LOOM_ACCEPT_V2_MIXED_LIFECYCLE
    $oldTUN = $env:LOOM_ACCEPT_TUN_LIFECYCLE
    $oldTombstone = $env:LOOM_ACCEPT_V2_TOMBSTONE_SCOPE
    try {
        $env:LOOM_ACCEPT_WINDOWS_V2 = '1'
        if ($ProfileRoot) { $env:LOOM_ACCEPT_V2_PROFILE_ROOT = (Resolve-Path -LiteralPath $ProfileRoot).Path }
        if ($InstalledInviteCarrier) {
            $env:LOOM_ACCEPT_INSTALLED_QR = (Resolve-Path -LiteralPath $InstalledInviteCarrier).Path
            Invoke-Checked 'installed_ui_join' 'go' @('test', '-count=1', '-vet=off', './clients/windows', '-run', '^TestInstalledGUIJoinLive$')
            $checks.installed_ui_join = $true
        }
        if ($InstalledResumeCarrier) {
            $env:LOOM_ACCEPT_INSTALLED_QR = (Resolve-Path -LiteralPath $InstalledResumeCarrier).Path
            Invoke-Checked 'installed_resume' 'go' @('test', '-count=1', '-vet=off', './clients/windows', '-run', '^TestInstalledGUIJoinLive$')
            $checks.installed_resume = $true
        }
        if ($RunInstalledLifecycle) {
            $env:LOOM_ACCEPT_INSTALLED = '1'
            Invoke-Checked 'installed_lifecycle' 'go' @('test', '-count=1', '-vet=off', './clients/windows', '-run', '^TestInstalled(ServiceLive|ConnectStopLive)$')
            $checks.installed_lifecycle = $true
        }
        if ($RunPortableMixedLifecycle) {
            $env:LOOM_ACCEPT_V2_MIXED_LIFECYCLE = '1'
            Invoke-Checked 'portable_mixed_lifecycle' 'go' @('test', '-count=1', '-vet=off', './clients/windows', '-run', '^TestWindowsV2PortableMixedLifecycleLive$')
            $checks.portable_mixed_lifecycle = $true
        }
        if ($RunPortableTUNLifecycle) {
            $env:LOOM_ACCEPT_TUN_LIFECYCLE = '1'
            Invoke-Checked 'portable_tun_lifecycle' 'go' @('test', '-count=1', '-vet=off', './clients/windows', '-run', '^TestWindowsTUNLifecycleLive$')
            $checks.portable_tun_lifecycle = $true
        }
        if ($TombstoneScope) {
            $env:LOOM_ACCEPT_V2_TOMBSTONE_SCOPE = $TombstoneScope
            Invoke-Checked 'tombstone_cleanup' 'go' @('test', '-count=1', '-vet=off', './clients/windows', '-run', '^TestWindowsV2TombstoneCleanupLive$')
            $checks["tombstone_cleanup_$TombstoneScope"] = $true
        }
    } finally {
        $env:LOOM_ACCEPT_WINDOWS_V2 = $oldV2
        $env:LOOM_ACCEPT_V2_PROFILE_ROOT = $oldProfileRoot
        $env:LOOM_ACCEPT_INSTALLED = $oldInstalled
        $env:LOOM_ACCEPT_INSTALLED_QR = $oldCarrier
        $env:LOOM_ACCEPT_V2_MIXED_LIFECYCLE = $oldMixed
        $env:LOOM_ACCEPT_TUN_LIFECYCLE = $oldTUN
        $env:LOOM_ACCEPT_V2_TOMBSTONE_SCOPE = $oldTombstone
    }
    if ($MultiProfileEvidencePath) {
        Add-EvidenceArtifact 'multi_profile_ui' $MultiProfileEvidencePath
        $checks.multi_profile_ui = $true
    }
    if ($UnderlayEvidencePath) {
        Add-EvidenceArtifact 'underlay_generation_change' $UnderlayEvidencePath
        $checks.underlay_generation_change = $true
    }
    $completed = $true
} catch {
    $failure = $activeCheck
    Write-Error $_.Exception.Message -ErrorAction Continue
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
    if ($locationPushed) { Pop-Location }
    $evidence = [ordered]@{
        schema = 1
        issue = 13
        generated_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        commit = $commit
        source_clean = $sourceClean
        host = [ordered]@{
            os = 'windows'
            architecture = $hostArchitecture
            version = [Environment]::OSVersion.Version.ToString()
        }
        checks = $checks
        evidence_artifacts = $evidenceArtifacts
        result = if ($completed) { 'passed' } else { 'failed' }
        failed_check = $failure
        contains_sensitive_runtime_data = $false
    }
    $json = $evidence | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($EvidencePath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Write-Output "Windows v2 host evidence: $EvidencePath"
}
if (-not $completed) { exit 1 }
