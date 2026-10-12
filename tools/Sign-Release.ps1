param(
    [Parameter(Mandatory=$true)][string]$InstallerPath,
    [Parameter(Mandatory=$true)][string]$MetadataPath,
    [Parameter(Mandatory=$true)][string]$PrivateKeyPath,
    [Parameter(Mandatory=$true)][string]$PublicKeyPath,
    [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$patchMetadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
$releaseVersion = [Version]$patchMetadata.patch_version
if ($releaseVersion.Revision -lt 0) { throw 'Use a four-part patch version.' }
$releaseTag = 'v{0}.{1}.{2}-ko.{3}' -f $releaseVersion.Major,$releaseVersion.Minor,$releaseVersion.Build,$releaseVersion.Revision
$installerHash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($installerHash -ne $patchMetadata.installer_sha256) { throw 'Installer hash does not match metadata.' }
$installerBytes = (Get-Item -LiteralPath $InstallerPath).Length
if ($installerBytes -le 0 -or $installerBytes -gt 64MB) { throw 'Installer exceeds updater size limit.' }
$updatePayload = [ordered]@{
    schema = 1
    version = $releaseVersion.ToString()
    installer_url = 'https://github.com/uckdoman/azeroth-survivors-korean/releases/download/' + $releaseTag + '/AzerothSurvivors_KoreanPatch.exe'
    installer_sha256 = $installerHash
    installer_size = $installerBytes
    source_exe_sha256 = $patchMetadata.supported_exe_sha256
    patched_exe_sha256 = $patchMetadata.patched_exe_sha256
    assets_sha256 = $patchMetadata.supported_assets_sha256
    overlay_sha256 = $patchMetadata.patch_mpq_sha256
}
foreach ($digestName in 'installer_sha256','source_exe_sha256','patched_exe_sha256','assets_sha256','overlay_sha256') {
    if ($updatePayload[$digestName] -cnotmatch '^[a-f0-9]{64}$') { throw "Invalid digest: $digestName" }
}
$releaseUtf8 = New-Object System.Text.UTF8Encoding($false)
$payloadBytes = $releaseUtf8.GetBytes(($updatePayload | ConvertTo-Json -Compress))
$releaseRsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
$releaseRsa.PersistKeyInCsp = $false
try {
    $releaseRsa.FromXmlString([System.IO.File]::ReadAllText($PrivateKeyPath))
    if ($releaseRsa.KeySize -ne 2048 -or $releaseRsa.ToXmlString($false) -ne ([System.IO.File]::ReadAllText($PublicKeyPath)).Trim([char]0xFEFF).Trim()) { throw 'Signing key does not match launcher public key.' }
    $signatureBytes = $releaseRsa.SignData($payloadBytes, [System.Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'))
    if (-not $releaseRsa.VerifyData($payloadBytes, [System.Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'), $signatureBytes)) { throw 'Signature self-check failed.' }
    $signedEnvelope = [ordered]@{ payload = [Convert]::ToBase64String($payloadBytes); signature = [Convert]::ToBase64String($signatureBytes) }
    [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($OutputPath), ($signedEnvelope | ConvertTo-Json -Compress), $releaseUtf8)
} finally { $releaseRsa.Dispose() }
Write-Output ('Signed release ' + $releaseVersion.ToString() + ' (' + $releaseTag + '). Private key was not included.')
