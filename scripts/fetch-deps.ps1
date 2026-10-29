param([string]$BuildRoot,[switch]$InstallInno)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\BuildPaths.ps1" -BuildRoot $BuildRoot
$deps=Join-Path $BuildRoot 'deps';New-Item -ItemType Directory -Force $deps | Out-Null
function Fetch-Verified([string]$url,[string]$path,[string]$sha)
{
    if(!(Test-Path -LiteralPath $path)){Invoke-WebRequest -Uri $url -OutFile $path}
    if((Get-FileHash -LiteralPath $path).Hash -ne $sha -or (Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid'){throw "Signature/hash mismatch: $path"}
}
Fetch-Verified 'https://github.com/namazso/PawnIO.Setup/releases/download/2.2.0/PawnIO_setup.exe' (Join-Path $deps 'PawnIO_setup.exe') '1F519A22E47187F70A1379A48CA604981C4FCF694F4E65B734AAA74A9FBA3032'
if($InstallInno)
{
    $installer=Join-Path $deps 'innosetup-6.7.3.exe'
    Fetch-Verified 'https://github.com/jrsoftware/issrc/releases/download/is-6_7_3/innosetup-6.7.3.exe' $installer '9C73C3BAE7ED48D44112A0F48E66742C00090BDB5BEF71D9D3C056C66E97B732'
    $target=Join-Path $BuildRoot 'tools\InnoSetup6'
    if(!(Test-Path (Join-Path $target 'ISCC.exe')))
    {
        $p=Start-Process $installer -ArgumentList '/CURRENTUSER','/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-','/NOICONS',('/DIR="'+$target+'"') -WindowStyle Hidden -PassThru
        if(!$p.WaitForExit(60000) -or $p.ExitCode -ne 0){throw 'Inno Setup installation failed'}
    }
}
