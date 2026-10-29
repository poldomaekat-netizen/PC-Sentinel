param([string]$BuildRoot)
$ProjectRoot=[IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if(!$BuildRoot){$BuildRoot=$env:PC_SENTINEL_BUILD_ROOT}
if(!$BuildRoot){$BuildRoot=if($env:RUNNER_TEMP){Join-Path $env:RUNNER_TEMP 'PCSentinel-Build'}else{Join-Path (Split-Path $ProjectRoot -Parent) 'PCSentinel-Build'}}
$BuildRoot=[IO.Path]::GetFullPath($BuildRoot)
if($BuildRoot -eq $ProjectRoot -or $BuildRoot.StartsWith($ProjectRoot+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'BuildRoot must be outside the source tree'}
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
$env:DOTNET_CLI_HOME=Join-Path $BuildRoot 'tools\cli'
$env:NUGET_PACKAGES=Join-Path $BuildRoot 'tools\nuget'
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$Dotnet=Join-Path $BuildRoot 'tools\dotnet\dotnet.exe'
if(!(Test-Path -LiteralPath $Dotnet)){$Dotnet='dotnet'}
$Version=([xml](Get-Content (Join-Path $ProjectRoot 'Directory.Build.props') -Raw)).Project.PropertyGroup.Version
function Assert-Exit([string]$stage){if($LASTEXITCODE -ne 0){throw "$stage failed ($LASTEXITCODE)"}}
function New-CleanPublish([string]$leaf)
{
    $base=[IO.Path]::GetFullPath((Join-Path $BuildRoot 'publish'))
    $path=[IO.Path]::GetFullPath((Join-Path $base $leaf))
    if(!$path.StartsWith($base+'\',[StringComparison]::OrdinalIgnoreCase) -or $path -eq $base){throw 'Unsafe publish cleanup target'}
    if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Recurse -Force}
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    return $path
}
function Write-Sha256([string]$path){"$((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)  $([IO.Path]::GetFileName($path))" | Set-Content -LiteralPath ($path+'.sha256')}
