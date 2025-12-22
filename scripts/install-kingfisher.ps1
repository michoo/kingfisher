<#
.SYNOPSIS
    Download and install a Kingfisher release for Windows.

.DESCRIPTION
    Fetches a GitHub release for mongodb/kingfisher, downloads the Windows x64
    archive, and extracts kingfisher.exe to the destination folder. By default
    the script installs into "$env:USERPROFILE\bin".

.PARAMETER InstallDir
    Optional destination directory for the kingfisher.exe binary.

.PARAMETER Tag
    Optional GitHub release tag (e.g., v1.71.0). Defaults to the latest release.

.EXAMPLE
    ./install-kingfisher.ps1

.EXAMPLE
    ./install-kingfisher.ps1 -InstallDir "C:\\Tools"

.EXAMPLE
    ./install-kingfisher.ps1 -Tag v1.71.0
#>
param(
    [Parameter(Position = 0)]
    [string]$InstallDir = (Join-Path $env:USERPROFILE 'bin'),

    [string]$Tag
)

$repo = 'mongodb/kingfisher'
$assetName = 'kingfisher-windows-x64.zip'

if (-not (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue)) {
    throw 'Invoke-WebRequest is required to download releases.'
}

if (-not (Get-Command Expand-Archive -ErrorAction SilentlyContinue)) {
    throw 'Expand-Archive is required to extract the release archive. Install the PowerShell archive module.'
}

if ($Tag) {
    $apiUrl = "https://api.github.com/repos/$repo/releases/tags/$Tag"
    Write-Host "Fetching release metadata for $repo tag $Tag…"
} else {
    $apiUrl = "https://api.github.com/repos/$repo/releases/latest"
    Write-Host "Fetching latest release metadata for $repo…"
}
try {
    $response = Invoke-WebRequest -Uri $apiUrl -UseBasicParsing
    $release = $response.Content | ConvertFrom-Json
} catch {
    throw "Failed to retrieve release information from GitHub: $_"
}

$releaseTag = $release.tag_name
$asset = $release.assets | Where-Object { $_.name -eq $assetName }
if (-not $asset) {
    throw "Could not find asset '$assetName' in the release metadata."
}

$tempDir = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) -Name ([System.Guid]::NewGuid().ToString())
$archivePath = Join-Path $tempDir.FullName $assetName

try {
    if ($releaseTag) {
        Write-Host "Latest release: $releaseTag"
    }

    Write-Host "Downloading $assetName…"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archivePath -UseBasicParsing

    Write-Host 'Extracting archive…'
    Expand-Archive -Path $archivePath -DestinationPath $tempDir.FullName -Force

    $binaryPath = Join-Path $tempDir.FullName 'kingfisher.exe'
    if (-not (Test-Path $binaryPath)) {
        throw 'Extracted archive did not contain kingfisher.exe.'
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $destination = Join-Path $InstallDir 'kingfisher.exe'
    Copy-Item -Path $binaryPath -Destination $destination -Force

    Write-Host "Kingfisher installed to: $destination"
    Write-Host "Ensure '$InstallDir' is in your PATH environment variable."
}
finally {
    if ($tempDir -and (Test-Path $tempDir.FullName)) {
        Remove-Item -Path $tempDir.FullName -Recurse -Force
    }
}
