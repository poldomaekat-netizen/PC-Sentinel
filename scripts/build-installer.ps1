param([string]$BuildRoot,[string]$Iscc,[string]$CertificateThumbprint,[switch]$SkipBuild)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\BuildPaths.ps1" -BuildRoot $BuildRoot
Set-Location $ProjectRoot
if(!$SkipBuild){& "$PSScriptRoot\build.ps1" -BuildRoot $BuildRoot -Packaging Folder;if(!$?){throw 'Folder build failed'}}
$source=Join-Path $BuildRoot "publish\v$Version-Folder"
if(!(Test-Path (Join-Path $source 'Service\PCSentinel.SensorService.exe'))){throw 'Folder app/service payload missing'}
if(!$Iscc){$Iscc=Join-Path $BuildRoot 'tools\InnoSetup6\ISCC.exe'}
if(!(Test-Path -LiteralPath $Iscc)){$Iscc='C:\Program Files (x86)\Inno Setup 6\ISCC.exe'}
if(!(Test-Path -LiteralPath $Iscc)){throw 'Install official Inno Setup 6.3+ or pass -Iscc'}
$driver=Join-Path $BuildRoot 'deps\PawnIO_setup.exe'
if(!(Test-Path -LiteralPath $driver)){$driver=Join-Path $BuildRoot 'artifacts\temperature-backend-review\PawnIO_setup.exe'}
if(Test-Path installer\deps\PawnIO_setup.exe){$driver=(Resolve-Path installer\deps\PawnIO_setup.exe).Path}
if(!(Test-Path -LiteralPath $driver)){throw 'Download official PawnIO 2.2.0 into installer/deps/PawnIO_setup.exe'}
if((Get-FileHash -LiteralPath $driver).Hash -ne '1F519A22E47187F70A1379A48CA604981C4FCF694F4E65B734AAA74A9FBA3032' -or (Get-AuthenticodeSignature -LiteralPath $driver).Status -ne 'Valid'){throw 'PawnIO signature/hash verification failed'}
$output=Join-Path $ProjectRoot 'installer\Output';New-Item -ItemType Directory -Force $output | Out-Null
$arguments=@("/DAppSource=$source","/DPawnIoSetup=$driver","/O$output")
if($CertificateThumbprint)
{
    foreach($file in Get-ChildItem -LiteralPath $source -Recurse -File | Where-Object {$_.Name -like 'PCSentinel*.exe' -or $_.Name -like 'PCSentinel*.dll'}){& "$PSScriptRoot\sign-file.ps1" -Path $file.FullName -CertificateThumbprint $CertificateThumbprint}
    $signScript=Join-Path $PSScriptRoot 'sign-file.ps1'
    $arguments+='/DSigningEnabled=1'
    $arguments+=('/Spcsentinel=powershell.exe -NoProfile -File $q'+$signScript+'$q -CertificateThumbprint '+$CertificateThumbprint+' -Path $f')
}
$arguments+='installer\PCSentinel.iss'
Get-ChildItem -LiteralPath $source -Recurse -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName | ForEach-Object {"$((Get-FileHash -LiteralPath $_.FullName).Hash)  $([IO.Path]::GetRelativePath($source,$_.FullName))"} | Set-Content (Join-Path $source 'SHA256SUMS.txt')
& $Iscc @arguments;Assert-Exit 'Inno compilation'
$setup=Join-Path $output "PCSentinel-$Version-Setup.exe"
Write-Sha256 $setup
Copy-Item -LiteralPath $setup -Destination (Join-Path $ProjectRoot ([IO.Path]::GetFileName($setup))) -Force
Copy-Item -LiteralPath ($setup+'.sha256') -Destination (Join-Path $ProjectRoot ([IO.Path]::GetFileName($setup)+'.sha256')) -Force
[pscustomobject]@{Version=$Version;FileVersion='0.3.2.1';AuthenticodeSigned=[bool]$CertificateThumbprint;Payload='Folder';DriverSHA256=(Get-FileHash $driver).Hash;SetupSHA256=(Get-FileHash $setup).Hash} | ConvertTo-Json | Set-Content (Join-Path $output 'BUILD-MANIFEST.json')
Write-Output "Installer: $setup"
