param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][string]$CertificateThumbprint,[string]$TimestampServer='http://timestamp.digicert.com')
$ErrorActionPreference='Stop'
$certificate=Get-Item ('Cert:\CurrentUser\My\'+$CertificateThumbprint)
if(!$certificate.HasPrivateKey -or $certificate.NotAfter -lt (Get-Date) -or $certificate.EnhancedKeyUsageList.ObjectId -notcontains '1.3.6.1.5.5.7.3.3'){throw 'A valid code-signing certificate with a private key is required'}
$result=Set-AuthenticodeSignature -FilePath $Path -Certificate $certificate -TimestampServer $TimestampServer -HashAlgorithm SHA256
if($result.Status -ne 'Valid'){throw "Signing failed: $($result.StatusMessage)"}
