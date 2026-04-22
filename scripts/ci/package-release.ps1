[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PlatformLabel,

    [Parameter(Mandatory = $true)]
    [ValidateSet('zip', 'tar.gz')]
    [string]$ArchiveFormat,

    [Parameter(Mandatory = $true)]
    [string]$CommitSha
)

$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$BinDir = Join-Path $RepoRoot 'zig-out\bin'
$DistRoot = Join-Path $RepoRoot 'dist'
$StageRoot = Join-Path $DistRoot $PlatformLabel
$BundleName = "shadowsocks-$PlatformLabel"
$BundleDir = Join-Path $StageRoot $BundleName
$ExeSuffix = if (Test-Path (Join-Path $BinDir 'sslocal.exe')) { '.exe' } else { '' }

$ExpectedBinaries = @(
    (Join-Path $BinDir "sslocal$ExeSuffix"),
    (Join-Path $BinDir "ssserver$ExeSuffix")
)

foreach ($Path in $ExpectedBinaries) {
    if (-not (Test-Path $Path)) {
        throw "Missing expected binary: $Path"
    }
}

Remove-Item -LiteralPath $StageRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $BundleDir -Force | Out-Null

Copy-Item -LiteralPath $ExpectedBinaries -Destination $BundleDir

$ReadmeText = @"
shadowsocks
platform: $PlatformLabel
commit: $CommitSha
source: GitHub Actions artifact build
"@

Set-Content -Path (Join-Path $BundleDir 'README.txt') -Value $ReadmeText

$ArchivePath = switch ($ArchiveFormat) {
    'zip'    { Join-Path $StageRoot "$BundleName.zip" }
    'tar.gz' { Join-Path $StageRoot "$BundleName.tar.gz" }
}

if ($ArchiveFormat -eq 'zip') {
    Compress-Archive -Path $BundleDir -DestinationPath $ArchivePath -Force
} else {
    & tar -czf $ArchivePath -C $StageRoot $BundleName
    if ($LASTEXITCODE -ne 0) {
        throw "tar failed with exit code $LASTEXITCODE"
    }
}

Write-Output $ArchivePath
