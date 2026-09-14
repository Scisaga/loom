param(
    [Parameter(Mandatory=$true)][string[]]$Evidence,
    [Parameter(Mandatory=$true)][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Evidence.Count -lt 2) { throw 'Gate B requires evidence from both native architectures.' }
$requiredPerArchitecture = @(
    'repository_safety', 'native_go_tests', 'native_v2_verifier', 'native_go_vet', 'native_dpapi_cng',
    'cross_compile_amd64', 'cross_compile_arm64', 'native_package_build_info',
    'installed_ui_join', 'installed_resume',
    'installed_lifecycle', 'portable_mixed_lifecycle', 'portable_tun_lifecycle',
    'tombstone_cleanup_user', 'tombstone_cleanup_machine',
    'multi_profile_ui', 'underlay_generation_change'
)
$requiredRelease = @(
    'six_zip_manifest', 'zip_exact_contents', 'dataplane_signatures',
    'two_msi_manifest', 'msi_database'
)
$byArchitecture = @{}
$releaseChecks = @{}
$commit = $null
$summaries = @()

foreach ($pathValue in $Evidence) {
    $path = (Resolve-Path -LiteralPath $pathValue).Path
    $raw = Get-Content -LiteralPath $path -Raw
    $item = $raw | ConvertFrom-Json
    if ($item.schema -ne 1 -or $item.issue -ne 13 -or $item.result -cne 'passed' -or
        $item.source_clean -ne $true -or $item.contains_sensitive_runtime_data -ne $false -or
        $item.host.os -cne 'windows' -or ($item.host.architecture -cne 'amd64' -and $item.host.architecture -cne 'arm64') -or
        $item.commit -notmatch '^[0-9a-f]{40}$') {
        throw "Invalid Windows v2 host evidence: $([IO.Path]::GetFileName($path))"
    }
    if ($null -eq $commit) { $commit = $item.commit }
    if ($item.commit -cne $commit) { throw 'Gate B evidence does not refer to one exact commit.' }
    foreach ($name in @('multi_profile_ui', 'underlay_generation_change')) {
        if ($item.checks.$name -eq $true) {
            $property = $item.evidence_artifacts.PSObject.Properties[$name]
            if ($null -eq $property -or $property.Value.sha256 -notmatch '^[0-9a-f]{64}$' -or
                $property.Value.size_bytes -lt 1 -or $property.Value.size_bytes -gt 64MB) {
                throw "Evidence artifact binding is missing or invalid: $name"
            }
        }
    }
    $architecture = $item.host.architecture
    if (-not $byArchitecture.ContainsKey($architecture)) { $byArchitecture[$architecture] = @{} }
    foreach ($name in $requiredPerArchitecture) {
        if ($item.checks.$name -eq $true) { $byArchitecture[$architecture][$name] = $true }
    }
    foreach ($name in $requiredRelease) {
        if ($item.checks.$name -eq $true) { $releaseChecks[$name] = $true }
    }
    $summaries += [ordered]@{
        architecture = $architecture
        generated_at = $item.generated_at
        evidence_sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

foreach ($architecture in @('amd64', 'arm64')) {
    if (-not $byArchitecture.ContainsKey($architecture)) { throw "Missing native $architecture evidence." }
    foreach ($name in $requiredPerArchitecture) {
        if (-not $byArchitecture[$architecture].ContainsKey($name)) {
            throw "Native $architecture evidence is missing: $name"
        }
    }
}
foreach ($name in $requiredRelease) {
    if (-not $releaseChecks.ContainsKey($name)) { throw "Release evidence is missing: $name" }
}

$parent = Split-Path -Parent $OutputPath
if (-not $parent) { throw 'OutputPath must include a parent directory.' }
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$report = [ordered]@{
    schema = 1
    issue = 13
    generated_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    commit = $commit
    architectures = @('amd64', 'arm64')
    host_evidence = $summaries
    release = [ordered]@{
        six_zips = $true
        two_msis = $true
        authenticode_blocking = $false
    }
    gate_b = $true
    contains_sensitive_runtime_data = $false
}
$json = $report | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($OutputPath, $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
Write-Output "Windows v2 Gate B evidence: $OutputPath"
