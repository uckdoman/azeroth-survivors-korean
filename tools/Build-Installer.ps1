param([string]$InputDirectory = (Join-Path $PSScriptRoot '..\inputs'), [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist'))
$ErrorActionPreference = 'Stop'
$repoSource = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\src'))
$buildInput = [IO.Path]::GetFullPath($InputDirectory)
$buildOutput = [IO.Path]::GetFullPath($OutputDirectory)
foreach ($name in 'translation-runtime.zip','FONT-LICENSE.txt','README.txt','release-template.json') {
    if (-not (Test-Path -LiteralPath (Join-Path $buildInput $name))) { throw "Missing input: $name" }
}
New-Item -ItemType Directory -Path $buildOutput -Force | Out-Null
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$launcher = Join-Path $buildOutput 'AzerothSurvivors_KoreanLauncher.exe'
$installer = Join-Path $buildOutput 'AzerothSurvivors_KoreanPatch.exe'
& $compiler /nologo /target:winexe /platform:anycpu /optimize+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll "/resource:$(Join-Path $repoSource 'release-public-key.xml'),release-public-key.xml" "/resource:$(Join-Path $repoSource 'initial-baseline.json'),initial-baseline.json" "/out:$launcher" (Join-Path $repoSource 'Launcher.cs')
if ($LASTEXITCODE -ne 0) { throw 'Launcher compile failed.' }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipPath = Join-Path $buildOutput ('.text-payload-' + [Guid]::NewGuid().ToString('N') + '.zip')
$archive = [IO.Compression.ZipFile]::Open($zipPath, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($name in 'FONT-LICENSE.txt','README.txt') {
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, (Join-Path $buildInput $name), $name, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally { $archive.Dispose() }
& $compiler /nologo /target:winexe /platform:anycpu /optimize+ /define:INSTALLER_BUILD /main:Installer /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll "/resource:$zipPath,patch.zip" "/resource:$(Join-Path $buildInput 'translation-runtime.zip'),translation-runtime.zip" "/resource:$launcher,launcher.exe" "/resource:$(Join-Path $repoSource 'release-public-key.xml'),release-public-key.xml" "/out:$installer" (Join-Path $repoSource 'Installer.cs') (Join-Path $repoSource 'InstallerUpdate.cs') (Join-Path $repoSource 'Launcher.cs')
if ($LASTEXITCODE -ne 0) { throw 'Installer compile failed.' }
Remove-Item -LiteralPath $zipPath
$metadata = Get-Content -LiteralPath (Join-Path $buildInput 'release-template.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$metadata.installer_sha256 = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
$metadata.installer_bytes = (Get-Item -LiteralPath $installer).Length
$metadata.launcher_sha256 = (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $buildOutput 'release-metadata.json'), ($metadata | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
Write-Output 'Translation-only installer built. No game or installer was launched.'
