param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [Parameter(Mandatory=$true)][uri]$TimestampUrl,
    [string]$SignTool = 'signtool.exe'
)
$ErrorActionPreference = 'Stop'
if ($CertificateThumbprint -notmatch '^[0-9a-fA-F]{40}$' -or $TimestampUrl.Scheme -ne 'https') {
    throw 'A certificate thumbprint and HTTPS RFC3161 timestamp URL are required.'
}
$artifact = (Resolve-Path -LiteralPath $Path).Path
$quotedArtifact = '"' + $artifact + '"'
$process = Start-Process -FilePath $SignTool -ArgumentList @('sign','/sha1',$CertificateThumbprint,'/fd','SHA256','/tr',$TimestampUrl.AbsoluteUri,'/td','SHA256',$quotedArtifact) -Wait -PassThru -NoNewWindow
if ($process.ExitCode -ne 0) { throw 'Authenticode signing failed.' }
$process = Start-Process -FilePath $SignTool -ArgumentList @('verify','/pa','/all',$quotedArtifact) -Wait -PassThru -NoNewWindow
if ($process.ExitCode -ne 0) { throw 'Authenticode verification failed.' }
$signature = Get-AuthenticodeSignature -LiteralPath $artifact
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint -or -not $signature.TimeStamperCertificate) {
    throw 'The artifact does not have the requested trusted, timestamped signature.'
}
