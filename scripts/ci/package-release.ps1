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
$ExeSuffix = if ($PlatformLabel -like 'windows-*') { '.exe' } else { '' }

$ExpectedBinaries = @(
    (Join-Path $BinDir "sslocal$ExeSuffix"),
    (Join-Path $BinDir "ssserver$ExeSuffix")
)

foreach ($Path in $ExpectedBinaries) {
    if (-not (Test-Path $Path)) {
        throw "Missing expected binary: $Path"
    }
}

New-Item -ItemType Directory -Path $StageRoot -Force | Out-Null
Remove-Item -LiteralPath $BundleDir -Recurse -Force -ErrorAction SilentlyContinue
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

Remove-Item -LiteralPath $ArchivePath -Force -ErrorAction SilentlyContinue

if ($ArchiveFormat -eq 'zip') {
    Compress-Archive -Path $BundleDir -DestinationPath $ArchivePath -Force
} else {
    & tar -czf $ArchivePath -C $StageRoot $BundleName
    if ($LASTEXITCODE -ne 0) {
        throw "tar failed with exit code $LASTEXITCODE"
    }
}

$ExpectedArchiveEntries = @(
    "$BundleName/README.txt",
    "$BundleName/sslocal$ExeSuffix",
    "$BundleName/ssserver$ExeSuffix"
)

if ($ArchiveFormat -eq 'zip') {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $ZipArchive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $ArchiveEntries = $ZipArchive.Entries | ForEach-Object { $_.FullName }
    } finally {
        $ZipArchive.Dispose()
    }
} else {
    $ArchiveEntries = & tar -tzf $ArchivePath
    if ($LASTEXITCODE -ne 0) {
        throw "tar verification failed with exit code $LASTEXITCODE"
    }
}

foreach ($ExpectedEntry in $ExpectedArchiveEntries) {
    if ($ExpectedEntry -notin $ArchiveEntries) {
        throw "Archive verification failed: missing '$ExpectedEntry' in $ArchivePath"
    }
}

Write-Output $ArchivePath
