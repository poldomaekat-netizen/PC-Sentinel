param([switch]$SmokeTest,[ValidateSet('Folder','SingleFile')][string]$Packaging='Folder',[string]$BuildRoot)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\BuildPaths.ps1" -BuildRoot $BuildRoot
Set-Location $ProjectRoot
& $Dotnet restore PCSentinel.sln --configfile NuGet.Config --lock-file-path packages.lock.json --locked-mode
Assert-Exit 'Locked restore'
& $Dotnet test PCSentinel.sln -c Release --no-restore --logger trx --results-directory (Join-Path $BuildRoot 'artifacts\tests')
Assert-Exit 'Tests'
$single=if($Packaging -eq 'SingleFile'){'true'}else{'false'}
$nativeExtract=$single
$publishLock=if($Packaging -eq 'SingleFile'){'packages.win-x64.singlefile.lock.json'}else{'packages.win-x64.folder.lock.json'}
$output=New-CleanPublish "v$Version-$Packaging"
& $Dotnet restore src\PCSentinel.App\PCSentinel.App.csproj -r win-x64 -p:SelfContained=true "-p:PublishSingleFile=$single" "-p:IncludeNativeLibrariesForSelfExtract=$nativeExtract" --configfile NuGet.Config --lock-file-path $publishLock --locked-mode
Assert-Exit 'Publish restore'
& $Dotnet publish src\PCSentinel.App\PCSentinel.App.csproj -c Release -r win-x64 --self-contained true "-p:PublishSingleFile=$single" "-p:IncludeNativeLibrariesForSelfExtract=$nativeExtract" --no-restore -o $output
Assert-Exit 'App publish'
if($Packaging -eq 'Folder')
{
    $serviceOutput=New-CleanPublish "service-$Version"
    & $Dotnet restore src\PCSentinel.SensorService\PCSentinel.SensorService.csproj -r win-x64 -p:SelfContained=true -p:PublishSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=false --configfile NuGet.Config --lock-file-path packages.win-x64.folder.lock.json --locked-mode
    Assert-Exit 'Service restore'
    & $Dotnet publish src\PCSentinel.SensorService\PCSentinel.SensorService.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:IncludeNativeLibrariesForSelfExtract=false --no-restore -o $serviceOutput
    Assert-Exit 'Service publish'
    # Keep the service's .NET Core runtime isolated from the UI's Windows Desktop runtime.
    # The privileged process has no WPF runtime and no single-file extraction at all.
    $serviceTarget=Join-Path $output 'Service';New-Item -ItemType Directory -Force $serviceTarget | Out-Null
    Get-ChildItem -LiteralPath $serviceOutput | Where-Object Extension -ne '.pdb' | Copy-Item -Destination $serviceTarget -Recurse
}
Get-ChildItem -LiteralPath $output -File -Filter '*.pdb' | Remove-Item -Force
Copy-Item docs\INSTALL.md (Join-Path $output 'README.md')
Copy-Item LICENSE-PC-Sentinel.txt,THIRD-PARTY-LICENSES.md $output
Copy-Item licenses (Join-Path $output 'licenses') -Recurse
$runtimeRoot=Split-Path (Get-Command $Dotnet).Source -Parent
foreach($notice in @('LICENSE.txt','ThirdPartyNotices.txt')){if(Test-Path (Join-Path $runtimeRoot $notice)){Copy-Item (Join-Path $runtimeRoot $notice) (Join-Path $output ('licenses\dotnet-'+$notice))}}
& $Dotnet list src\PCSentinel.App\PCSentinel.App.csproj package --include-transitive --no-restore | Set-Content (Join-Path $output 'DEPENDENCIES.txt')
Assert-Exit 'Dependency inventory'
Get-ChildItem -LiteralPath $output -Recurse -File | Sort-Object FullName | ForEach-Object {"$((Get-FileHash -LiteralPath $_.FullName).Hash)  $([IO.Path]::GetRelativePath($output,$_.FullName))"} | Set-Content (Join-Path $output 'SHA256SUMS.txt')
if($Packaging -eq 'SingleFile')
{
    $portable=Join-Path $ProjectRoot "PCSentinel-v$Version.exe"
    if(Test-Path -LiteralPath $portable){$legacy=Join-Path $BuildRoot ('legacy\'+(Get-Date -Format yyyyMMdd-HHmmss));New-Item -ItemType Directory -Path $legacy -Force | Out-Null;Copy-Item -LiteralPath $portable -Destination $legacy}
    Copy-Item (Join-Path $output 'PCSentinel.exe') $portable -Force;Write-Sha256 $portable
}
foreach($exe in Get-ChildItem -LiteralPath $ProjectRoot -File -Filter 'PCSentinel*.exe'){Write-Sha256 $exe.FullName}
if($SmokeTest)
{
    $data=Join-Path $BuildRoot ('artifacts\smoke-'+(Get-Date -Format yyyyMMdd-HHmmss))
    $process=Start-Process (Join-Path $output 'PCSentinel.exe') -ArgumentList ('--smoke-test --data-dir "'+$data+'"') -WindowStyle Hidden -PassThru
    if(!$process.WaitForExit(45000) -or $process.ExitCode -ne 0){throw 'Smoke test failed or timed out'}
    $result=Get-Content (Join-Path $data 'smoke-result.json') -Raw | ConvertFrom-Json
    if($result.samples -lt 5 -or !$result.uiRendered){throw 'Missing smoke evidence'}
    Write-Output "Smoke passed: $data"
}
Write-Output "Published $Packaging build: $output"
