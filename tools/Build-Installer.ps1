param([string]$InputDirectory = (Join-Path $PSScriptRoot '..\inputs'), [string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist'))
$ErrorActionPreference = 'Stop'
$repoSource = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\src'))
$buildInput = [System.IO.Path]::GetFullPath($InputDirectory)
$buildOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
foreach ($inputFile in 'game.delta','patch-Z.MPQ','FONT-LICENSE.txt','README.txt') {
    if (-not (Test-Path -LiteralPath (Join-Path $buildInput $inputFile))) { throw "Missing input: $inputFile" }
}
New-Item -ItemType Directory -Path $buildOutput -Force | Out-Null
$sourceGamePath = Join-Path $repoSource 'source-game.json'
$sourceGameMetadata = Get-Content -LiteralPath $sourceGamePath -Raw -Encoding UTF8 | ConvertFrom-Json
$sourceGameArchive = Join-Path $buildInput 'game-source.gz'
if (-not (Test-Path -LiteralPath $sourceGameArchive) -or (Get-Item -LiteralPath $sourceGameArchive).Length -ne $sourceGameMetadata.compressed_size -or (Get-FileHash -LiteralPath $sourceGameArchive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $sourceGameMetadata.compressed_sha256) { throw 'Supported game archive does not match this release.' }
$buildCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $buildCompiler)) { $buildCompiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
$buildLauncher = Join-Path $buildOutput 'AzerothSurvivors_KoreanLauncher.exe'
$buildInstaller = Join-Path $buildOutput 'AzerothSurvivors_KoreanPatch.exe'
& $buildCompiler /nologo /target:winexe /platform:anycpu /optimize+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll "/resource:$(Join-Path $repoSource 'release-public-key.xml'),release-public-key.xml" "/resource:$(Join-Path $repoSource 'initial-baseline.json'),initial-baseline.json" "/out:$buildLauncher" (Join-Path $repoSource 'Launcher.cs')
if ($LASTEXITCODE -ne 0) { throw 'Launcher compile failed.' }
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$buildZip = Join-Path $buildOutput ('.patch-' + [Guid]::NewGuid().ToString('N') + '.zip')
$buildArchive = [System.IO.Compression.ZipFile]::Open($buildZip, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($inputFile in 'game.delta','patch-Z.MPQ','FONT-LICENSE.txt','README.txt') {
        [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($buildArchive, (Join-Path $buildInput $inputFile), $inputFile, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally { $buildArchive.Dispose() }
& $buildCompiler /nologo /target:winexe /platform:anycpu /optimize+ /define:INSTALLER_BUILD /main:Installer /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll "/resource:$buildZip,patch.zip" "/resource:$buildLauncher,launcher.exe" "/resource:$(Join-Path $repoSource 'release-public-key.xml'),release-public-key.xml" "/resource:$sourceGamePath,source-game.json" "/resource:$sourceGameArchive,source-game.gz" "/out:$buildInstaller" (Join-Path $repoSource 'Installer.cs') (Join-Path $repoSource 'InstallerUpdate.cs') (Join-Path $repoSource 'Launcher.cs') (Join-Path $repoSource 'SupportedGame.cs')
if ($LASTEXITCODE -ne 0) { throw 'Installer compile failed.' }
Remove-Item -LiteralPath $buildZip
$buildSourceText = Get-Content -LiteralPath (Join-Path $repoSource 'Installer.cs') -Raw -Encoding UTF8
function Read-BuildConstant([string]$ConstantName) {
    $buildMatch = [regex]::Match($buildSourceText, ('const string ' + [regex]::Escape($ConstantName) + ' = "([^"]+)";'))
    if (-not $buildMatch.Success) { throw "Missing constant: $ConstantName" }
    return $buildMatch.Groups[1].Value
}
$actualOverlayHash = (Get-FileHash -LiteralPath (Join-Path $buildInput 'patch-Z.MPQ') -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualOverlayHash -ne (Read-BuildConstant 'OverlayHash')) { throw 'Input overlay hash does not match installer.' }
$buildBaseline = Get-Content -LiteralPath (Join-Path $repoSource 'initial-baseline.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($buildBaseline.version -ne (Read-BuildConstant 'PatchVersion') -or $buildBaseline.source_exe_sha256 -ne (Read-BuildConstant 'OriginalHash') -or $buildBaseline.patched_exe_sha256 -ne (Read-BuildConstant 'PatchedHash') -or $buildBaseline.assets_sha256 -ne (Read-BuildConstant 'AssetsHash') -or $buildBaseline.overlay_sha256 -ne $actualOverlayHash) { throw 'Launcher baseline does not match installer constants.' }
if ($sourceGameMetadata.sha256 -ne (Read-BuildConstant 'OriginalHash') -or $sourceGameMetadata.version -ne ([Version](Read-BuildConstant 'PatchVersion')).ToString(3)) { throw 'Supported game download does not match this release.' }
$buildMetadata = [ordered]@{
    patch_version = Read-BuildConstant 'PatchVersion'
    installer_sha256 = (Get-FileHash -LiteralPath $buildInstaller -Algorithm SHA256).Hash.ToLowerInvariant()
    supported_exe_sha256 = Read-BuildConstant 'OriginalHash'
    supported_assets_sha256 = Read-BuildConstant 'AssetsHash'
    patched_exe_sha256 = Read-BuildConstant 'PatchedHash'
    patch_mpq_sha256 = $actualOverlayHash
    supported_patch2_sha256 = Read-BuildConstant 'Patch2Hash'
}
$buildUtf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $buildOutput 'release-metadata.json'), ($buildMetadata | ConvertTo-Json), $buildUtf8)
Write-Output 'Installer built. No game or installer was launched.'
