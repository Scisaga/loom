$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$stateRoot = 'C:\LoomTest'
$runsRoot = Join-Path $stateRoot 'runs'
$logsRoot = Join-Path $stateRoot 'logs'
New-Item -ItemType Directory -Force -Path $stateRoot, $runsRoot, $logsRoot | Out-Null
Start-Transcript -LiteralPath (Join-Path $logsRoot 'bootstrap.log') -Append | Out-Null

function Remove-BootstrapSecrets {
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty -LiteralPath $winlogon -Name AutoAdminLogon -Value '0'
    Remove-ItemProperty -LiteralPath $winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
    Remove-ItemProperty -LiteralPath $winlogon -Name AutoLogonCount -ErrorAction SilentlyContinue
    foreach ($cachedAnswerFile in @(
        'C:\Windows\Panther\unattend.xml',
        'C:\Windows\Panther\Unattend\unattend.xml'
    )) {
        Remove-Item -LiteralPath $cachedAnswerFile -Force -ErrorAction SilentlyContinue
    }
}

try {

# Keep the host-only forwarded management path separate from the data interface
# that Loom is allowed to exercise and disrupt.
$mgmtMac = '525400110001'
$dataMac = '525400110002'
$adapters = Get-NetAdapter
$mgmt = $adapters | Where-Object { ($_.MacAddress -replace '-', '') -eq $mgmtMac }
$data = $adapters | Where-Object { ($_.MacAddress -replace '-', '') -eq $dataMac }
if (-not $mgmt -or -not $data) {
    throw 'The expected management and data adapters are not present.'
}
if ($mgmt.Name -ne 'LoomMgmt') {
    Rename-NetAdapter -Name $mgmt.Name -NewName 'LoomMgmt'
}
if ($data.Name -ne 'LoomData') {
    Rename-NetAdapter -Name $data.Name -NewName 'LoomData'
}
$mgmt = Get-NetAdapter -Name 'LoomMgmt'
$data = Get-NetAdapter -Name 'LoomData'

Set-NetIPInterface -InterfaceIndex $mgmt.ifIndex -AddressFamily IPv4 -Dhcp Disabled
Get-NetIPAddress -InterfaceIndex $mgmt.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceIndex $mgmt.ifIndex -IPAddress '10.0.2.15' -PrefixLength 24 | Out-Null
Get-NetRoute -InterfaceIndex $mgmt.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
Set-NetIPInterface -InterfaceIndex $mgmt.ifIndex -AddressFamily IPv4 -InterfaceMetric 5000
Set-NetIPInterface -InterfaceIndex $data.ifIndex -AddressFamily IPv4 -InterfaceMetric 10
Set-DnsClientServerAddress -InterfaceIndex $data.ifIndex -ServerAddresses '@@DATA_DNS@@'

$httpProxy = '@@HTTP_PROXY@@'
if ($httpProxy) {
    $proxyUri = [Uri]$httpProxy
    [Environment]::SetEnvironmentVariable('HTTP_PROXY', $httpProxy, 'Machine')
    [Environment]::SetEnvironmentVariable('HTTPS_PROXY', $httpProxy, 'Machine')
    & netsh.exe winhttp set proxy $proxyUri.Authority | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'WinHTTP proxy configuration failed.' }
}

$sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
if (-not $sshdService) {
    $seedVolume = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'LOOMSEED' }
    if (-not $seedVolume -or -not $seedVolume.DriveLetter) {
        throw 'The one-time provisioning volume is unavailable.'
    }
    $openSshMsi = $seedVolume.DriveLetter + ':\OpenSSH.msi'
    $expectedOpenSshHash = '@@OPENSSH_SHA256@@'
    $actualOpenSshHash = (Get-FileHash -LiteralPath $openSshMsi -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualOpenSshHash -ne $expectedOpenSshHash) {
        throw 'The offline OpenSSH management package failed its SHA-256 check.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $openSshMsi
    if ($signature.Status -ne 'Valid') {
        throw 'The offline OpenSSH management package does not have a valid Authenticode signature.'
    }
    $installer = Start-Process -FilePath msiexec.exe -ArgumentList @(
        '/i', $openSshMsi, 'ADDLOCAL=Server', '/qn', '/norestart'
    ) -Wait -PassThru
    if ($installer.ExitCode -notin @(0, 3010)) {
        throw "OpenSSH management package installation failed with exit code $($installer.ExitCode)."
    }
    $sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $sshdService) { throw 'OpenSSH Server installation did not create the sshd service.' }
}

Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd

$sshdExecutable = @(
    'C:\Windows\System32\OpenSSH\sshd.exe',
    'C:\Program Files\OpenSSH\sshd.exe'
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $sshdExecutable) { throw 'The sshd executable is unavailable after installation.' }
$sftpExecutable = Join-Path (Split-Path -Parent $sshdExecutable) 'sftp-server.exe'
if (-not (Test-Path -LiteralPath $sftpExecutable -PathType Leaf)) {
    throw 'The SFTP executable is unavailable after installation.'
}

$sshConfig = 'C:\ProgramData\ssh\sshd_config'
$config = Get-Content -LiteralPath $sshConfig -Raw
$firstMatch = [regex]::Match($config, '(?mi)^\s*Match\s+')
if ($firstMatch.Success) {
    $globalConfig = $config.Substring(0, $firstMatch.Index)
    $matchConfig = $config.Substring($firstMatch.Index)
} else {
    $globalConfig = $config
    $matchConfig = ''
}
foreach ($directive in @(
    'PubkeyAuthentication',
    'PasswordAuthentication',
    'KbdInteractiveAuthentication',
    'AuthenticationMethods',
    'AuthorizedKeysFile',
    'ListenAddress',
    'AllowUsers',
    'Subsystem'
)) {
    $pattern = '(?mi)^\s*#?\s*' + [regex]::Escape($directive) + '\s+.*\r?\n?'
    $globalConfig = [regex]::Replace($globalConfig, $pattern, '')
}
$managedConfig = @"
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
ListenAddress 10.0.2.15
AllowUsers loomtest
Subsystem sftp "$($sftpExecutable -replace '\\', '/')"
"@
$config = $globalConfig.TrimEnd() + "`r`n" + $managedConfig.Trim() + "`r`n"
if ($matchConfig) { $config += $matchConfig.TrimStart() }
Set-Content -LiteralPath $sshConfig -Value $config -Encoding ascii

$adminKeys = 'C:\ProgramData\ssh\administrators_authorized_keys'
Set-Content -LiteralPath $adminKeys -Value '@@SSH_PUBLIC_KEY@@' -Encoding ascii
& icacls.exe $adminKeys /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F' | Out-Null
& $sshdExecutable -t
if ($LASTEXITCODE -ne 0) { throw 'Generated sshd_config did not pass sshd -t.' }
Restart-Service -Name sshd

$defaultSshRule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
if ($defaultSshRule) {
    $defaultSshRule | Disable-NetFirewallRule
}
if (-not (Get-NetFirewallRule -Name 'Loom-Test-SSH' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'Loom-Test-SSH' -DisplayName 'Loom test SSH management' `
        -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 `
        -InterfaceAlias 'LoomMgmt' -Profile Any | Out-Null
}

# Expose RDP only through QEMU's localhost forwarding. Firewall rule names are
# stable identifiers and therefore do not depend on the guest UI language.
Set-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Get-NetFirewallRule -Name 'RemoteDesktop-*' -ErrorAction SilentlyContinue |
    Set-NetFirewallRule -Enabled True -InterfaceAlias 'LoomMgmt'
Set-Service -Name TermService -StartupType Automatic
Start-Service -Name TermService

& powercfg.exe /hibernate off
& powercfg.exe /change standby-timeout-ac 0
& powercfg.exe /change monitor-timeout-ac 0

& icacls.exe $stateRoot /inheritance:r /grant '*S-1-5-18:(OI)(CI)F' /grant '*S-1-5-32-544:(OI)(CI)F' | Out-Null

$interactiveScript = Join-Path $stateRoot 'interactive-job.ps1'
Set-Content -LiteralPath $interactiveScript -Encoding utf8 -Value @'
$ErrorActionPreference = 'Stop'
$request = 'C:\LoomTest\interactive-job.json'
if (-not (Test-Path -LiteralPath $request)) { exit 0 }
$job = Get-Content -LiteralPath $request -Raw | ConvertFrom-Json
$run = [IO.Path]::GetFullPath([string]$job.run)
$root = [IO.Path]::GetFullPath('C:\LoomTest\runs') + [IO.Path]::DirectorySeparatorChar
if (-not $run.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Interactive job path is outside C:\LoomTest\runs.'
}
$script = Join-Path $run 'run.ps1'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
    throw 'Interactive job does not contain run.ps1.'
}
$output = Join-Path $run 'interactive-output.txt'
try {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $script *>&1 |
        Out-File -LiteralPath $output -Encoding utf8
    $LASTEXITCODE | Set-Content -LiteralPath (Join-Path $run 'interactive-exit-code.txt') -Encoding ascii
} catch {
    $_ | Out-File -LiteralPath $output -Append -Encoding utf8
    '1' | Set-Content -LiteralPath (Join-Path $run 'interactive-exit-code.txt') -Encoding ascii
    throw
}
'@

$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\LoomTest\interactive-job.ps1'
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\loomtest" -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName 'LoomInteractiveTest' -Action $taskAction -Principal $taskPrincipal -Force | Out-Null

$provisioningVolume = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'LOOMSEED' }
if (-not $provisioningVolume -or -not $provisioningVolume.DriveLetter) {
    throw 'The one-time provisioning volume is unavailable for verifier installation.'
}
$verifySource = $provisioningVolume.DriveLetter + ':\verify-executor.ps1'
if (-not (Test-Path -LiteralPath $verifySource -PathType Leaf)) {
    throw 'The executor verifier is missing from the one-time provisioning volume.'
}
Copy-Item -LiteralPath $verifySource -Destination (Join-Path $stateRoot 'verify-executor.ps1') -Force

$marker = [ordered]@{
    schema = 1
    purpose = 'loom-windows-native-test-executor'
    computer = $env:COMPUTERNAME
    user = $env:USERNAME
    completed_utc = [DateTime]::UtcNow.ToString('o')
}
$marker | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stateRoot 'bootstrap-complete.json') -Encoding utf8
} catch {
    [ordered]@{
        schema = 1
        failed_utc = [DateTime]::UtcNow.ToString('o')
        exception = $_.Exception.GetType().FullName
        message = $_.Exception.Message
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $logsRoot 'bootstrap-error.json') -Encoding utf8
    throw
} finally {
    # AutoLogon is needed exactly once to register the interactive task in the
    # intended desktop account. Never retain its reusable plaintext password,
    # even when provisioning fails and must be repaired from the local console.
    Remove-BootstrapSecrets
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
}
