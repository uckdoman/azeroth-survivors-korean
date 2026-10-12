param(
    [Parameter(Mandatory=$true)][string]$InstallerPath,
    [Parameter(Mandatory=$true)][string]$MetadataPath,
    [Parameter(Mandatory=$true)][string]$PrivateKeyPath,
    [Parameter(Mandatory=$true)][string]$ReleaseNotesPath,
    [switch]$DraftOnly
)
$ErrorActionPreference = 'Stop'
$releaseRepo = 'uckdoman/azeroth-survivors-korean'
$releaseMetadata = Get-Content -LiteralPath $MetadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
$releaseVersion = [Version]$releaseMetadata.patch_version
$releaseTag = 'v{0}.{1}.{2}-ko.{3}' -f $releaseVersion.Major,$releaseVersion.Minor,$releaseVersion.Build,$releaseVersion.Revision
$releaseFolder = Split-Path -Parent ([System.IO.Path]::GetFullPath($InstallerPath))
$releaseFeed = Join-Path $releaseFolder 'update.json'
$releasePublicKey = Join-Path $PSScriptRoot '..\src\release-public-key.xml'
& (Join-Path $PSScriptRoot 'Sign-Release.ps1') -InstallerPath $InstallerPath -MetadataPath $MetadataPath -PrivateKeyPath $PrivateKeyPath -PublicKeyPath $releasePublicKey -OutputPath $releaseFeed
# Publish only after both the installer and its signed manifest are uploaded.
& gh release create $releaseTag $InstallerPath $releaseFeed --repo $releaseRepo --draft --title ('한국어 패치 ' + $releaseVersion.ToString()) --notes-file $ReleaseNotesPath
if ($LASTEXITCODE -ne 0) { throw 'Draft release creation failed. No existing release was overwritten.' }
if (-not $DraftOnly) {
    $draftReleases = & gh api "repos/$releaseRepo/releases?per_page=100" | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Could not find the uploaded draft.' }
    $matchingDraft = @($draftReleases | Where-Object { $_.tag_name -eq $releaseTag -and $_.draft })
    if ($matchingDraft.Count -ne 1) { throw 'Expected exactly one matching draft release.' }
    & gh api --method PATCH "repos/$releaseRepo/releases/$($matchingDraft[0].id)" -F draft=false -f make_latest=true --jq .html_url
    if ($LASTEXITCODE -ne 0) { throw 'Publishing failed; the draft assets are preserved.' }
}
