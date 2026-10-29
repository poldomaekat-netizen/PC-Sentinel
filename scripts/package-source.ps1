param([string]$BuildRoot)
$ErrorActionPreference='Stop'
. "$PSScriptRoot\BuildPaths.ps1" -BuildRoot $BuildRoot
Add-Type -AssemblyName System.IO.Compression
$output=Join-Path $ProjectRoot "installer\Output\PCSentinel-$Version-Source.zip"
New-Item -ItemType Directory -Force (Split-Path $output -Parent) | Out-Null
$files=@()
foreach($dir in @('src','tests','scripts','installer','licenses','.github'))
{
    $files+=Get-ChildItem -LiteralPath (Join-Path $ProjectRoot $dir) -Recurse -File -Force | Where-Object {
        $relative=[IO.Path]::GetRelativePath($ProjectRoot,$_.FullName)
        $relative -notmatch '(^|[\\/])(bin|obj|Output|deps|TestResults)([\\/]|$)' -and $_.Extension -notin @('.exe','.pfx','.p12','.key','.snk','.user')
    }
}
foreach($name in @('PCSentinel.sln','Directory.Build.props','global.json','NuGet.Config','.gitignore','README.md','LICENSE-PC-Sentinel.txt','THIRD-PARTY-LICENSES.md','docs\INSTALL.md','docs\BUILD-INSTALLER.md','docs\RELEASE-NOTES-v0.3.2.md','docs\TESTING.md'))
{if(Test-Path (Join-Path $ProjectRoot $name)){$files+=Get-Item (Join-Path $ProjectRoot $name)}}
$stream=[IO.File]::Open($output,[IO.FileMode]::Create);$zip=[IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
try{foreach($file in $files | Sort-Object FullName -Unique){[IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$file.FullName,[IO.Path]::GetRelativePath($ProjectRoot,$file.FullName).Replace('\','/'),[IO.Compression.CompressionLevel]::Optimal) | Out-Null}}
finally{$zip.Dispose();$stream.Dispose()}
Write-Sha256 $output
Write-Output "Source package: $output"
