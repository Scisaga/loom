$ErrorActionPreference = 'Stop'
$failures = New-Object 'System.Collections.Generic.List[string]'
function Assert-State {
    param([string]$Name, [bool]$Condition)
    if (-not $Condition) { $failures.Add($Name) }
}

$os = Get-CimInstance Win32_OperatingSystem
$edition = (Get-WindowsEdition -Online).Edition
$marker = Get-Content C:\LoomTest\bootstrap-complete.json -Raw | ConvertFrom-Json
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$administrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$tpm = Get-Tpm
try { $secureBoot = [bool](Confirm-SecureBootUEFI) } catch { $secureBoot = $false }
$sshConfigText = Get-Content C:\ProgramData\ssh\sshd_config -Raw
$sshService = Get-Service sshd
$sshStartMode = (Get-CimInstance Win32_Service -Filter "Name='sshd'").StartMode
$sshRule = Get-NetFirewallRule -Name 'Loom-Test-SSH'
$sshInterface = Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $sshRule
$rdpRules = @(Get-NetFirewallRule -Name 'RemoteDesktop-*' | Where-Object { $_.Enabled -eq 'True' })
$mgmt = Get-NetAdapter -Name 'LoomMgmt' -ErrorAction SilentlyContinue
$data = Get-NetAdapter -Name 'LoomData' -ErrorAction SilentlyContinue
$mgmtAddress = @(Get-NetIPAddress -InterfaceAlias 'LoomMgmt' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -eq '10.0.2.15' })
$mgmtDefaultRoute = @(Get-NetRoute -InterfaceAlias 'LoomMgmt' -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
$winlogon = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$passwordAbsent = -not ($winlogon.PSObject.Properties.Name -contains 'DefaultPassword')
$rdpEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0
$rdpService = Get-Service TermService
$sshPublicKeyOnly = ($sshConfigText -match '(?m)^\s*PasswordAuthentication\s+no\s*$') -and ($sshConfigText -match '(?m)^\s*KbdInteractiveAuthentication\s+no\s*$') -and ($sshConfigText -match '(?m)^\s*AuthenticationMethods\s+publickey\s*$')
$sftpMatch = [regex]::Match($sshConfigText, '(?mi)^\s*Subsystem\s+sftp\s+"?([^"\r\n]+)"?\s*$')
$sftpPath = if ($sftpMatch.Success) { $sftpMatch.Groups[1].Value.Trim() } else { '' }
$sftpAbsolutePath = $sftpPath -and [IO.Path]::IsPathRooted($sftpPath) -and (Test-Path -LiteralPath $sftpPath -PathType Leaf)
$rdpWrongInterface = @($rdpRules | Where-Object {
    $interface = Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $_
    @($interface.InterfaceAlias).Count -ne 1 -or $interface.InterfaceAlias -notcontains 'LoomMgmt'
})
$rdpManagementOnly = ($rdpRules.Count -gt 0) -and ($rdpWrongInterface.Count -eq 0)

Assert-State 'edition' ($edition -eq 'Professional')
Assert-State 'bootstrap-purpose' ($marker.purpose -eq 'loom-windows-native-test-executor')
Assert-State 'administrator' $administrator
Assert-State 'tpm-present' ([bool]$tpm.TpmPresent)
Assert-State 'tpm-ready' ([bool]$tpm.TpmReady)
Assert-State 'secure-boot' $secureBoot
Assert-State 'ssh-running' ($sshService.Status -eq 'Running')
Assert-State 'ssh-autostart' ($sshStartMode -eq 'Auto')
Assert-State 'ssh-public-key-only' $sshPublicKeyOnly
Assert-State 'sftp-absolute-path' $sftpAbsolutePath
Assert-State 'ssh-management-listener' ($sshConfigText -match '(?m)^\s*ListenAddress\s+10\.0\.2\.15\s*$')
Assert-State 'ssh-management-firewall' ($sshRule.Enabled -eq 'True' -and @($sshInterface.InterfaceAlias).Count -eq 1 -and $sshInterface.InterfaceAlias -contains 'LoomMgmt')
Assert-State 'rdp-enabled' ($rdpEnabled -and $rdpService.Status -eq 'Running')
Assert-State 'rdp-management-firewall' $rdpManagementOnly
Assert-State 'management-nic' ([bool]$mgmt -and $mgmtAddress.Count -eq 1 -and $mgmtDefaultRoute.Count -eq 0)
Assert-State 'data-nic' ([bool]$data)
Assert-State 'autologon-disabled' ($winlogon.AutoAdminLogon -eq '0' -and $passwordAbsent)
Assert-State 'administrator-key' (Test-Path C:\ProgramData\ssh\administrators_authorized_keys -PathType Leaf)

$result = [ordered]@{
    EditionID = $edition
    Version = $os.Version
    Is64BitOperatingSystem = [Environment]::Is64BitOperatingSystem
    BootstrapPurpose = $marker.purpose
    Administrator = $administrator
    TpmPresent = [bool]$tpm.TpmPresent
    TpmReady = [bool]$tpm.TpmReady
    SecureBoot = $secureBoot
    SshPublicKeyOnly = $sshPublicKeyOnly
    SftpAbsolutePath = [bool]$sftpAbsolutePath
    ManagementNic = [bool]$mgmt
    DataNic = [bool]$data
    AutoLogonDisabled = $winlogon.AutoAdminLogon -eq '0' -and $passwordAbsent
    Failures = @($failures)
}
$result | ConvertTo-Json -Compress
if ($failures.Count -ne 0) { exit 1 }
