<#
Phase 2 Windows installer.

This is an explicit, isolated install only. It verifies the package-provided
daemon before creating or changing the requested destination.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $Destination
)

$ErrorActionPreference = "Stop"

if (-not $PSBoundParameters.ContainsKey("Destination") -or [string]::IsNullOrWhiteSpace($Destination)) {
    throw "-Destination is mandatory and must name an isolated destination."
}

function ConvertTo-NormalizedPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    if (-not [IO.Path]::IsPathRooted($expanded)) {
        $expanded = Join-Path -Path (Get-Location).Path -ChildPath $expanded
    }
    $full = [IO.Path]::GetFullPath($expanded).Replace([char]'/', [char]'\')
    $trimmed = $full.TrimEnd([char]'\')
    if ($trimmed -match '^[A-Za-z]:$') {
        return "$trimmed\"
    }
    return $trimmed
}

function Test-PathUnder {
    param(
        [Parameter(Mandatory = $true)][string] $Candidate,
        [Parameter(Mandatory = $true)][string] $Root
    )

    return [string]::Equals($Candidate, $Root, [StringComparison]::OrdinalIgnoreCase) -or
        $Candidate.StartsWith("$Root\", [StringComparison]::OrdinalIgnoreCase)
}

function Assert-IsolatedDestination {
    param([Parameter(Mandatory = $true)][string] $Path)

    $normalized = ConvertTo-NormalizedPath $Path
    $homeOpenLlm = ConvertTo-NormalizedPath (Join-Path -Path $HOME -ChildPath ".openllm")
    $programDataOpenLlm = ConvertTo-NormalizedPath (Join-Path -Path $env:ProgramData -ChildPath "openllm")
    $userHomePattern = '^[A-Za-z]:\\Users\\[^\\]+\\\.openllm(?:\\|$)'
    $programDataPattern = '^[A-Za-z]:\\ProgramData\\openllm(?:\\|$)'

    if (
        (Test-PathUnder $normalized $homeOpenLlm) -or
        (Test-PathUnder $normalized $programDataOpenLlm) -or
        ($normalized -match $userHomePattern) -or
        ($normalized -match $programDataPattern)
    ) {
        throw "Destination resolves into a production home and is refused: $Path"
    }
    return $normalized
}

function Assert-NoReparsePointInPath {
    param([Parameter(Mandatory = $true)][string] $Path)

    $current = $Path
    while (-not [string]::IsNullOrEmpty($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Destination contains a reparse point and is refused: $current"
            }
        }
        $parent = Split-Path $current -Parent
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $current) { break }
        $current = $parent
    }
}

$resolvedDestination = Assert-IsolatedDestination $Destination
Assert-NoReparsePointInPath $resolvedDestination
if (Test-Path -LiteralPath $resolvedDestination -PathType Leaf) {
    throw "-Destination must be a directory: $Destination"
}

$packageDaemon = Join-Path -Path $PSScriptRoot -ChildPath "bin\openllmd.exe"
$packageSums = Join-Path -Path $PSScriptRoot -ChildPath "SHA256SUMS"
if (-not (Test-Path -LiteralPath $packageDaemon -PathType Leaf)) {
    throw "Package is missing bin\openllmd.exe; refusing to install."
}
if (-not (Test-Path -LiteralPath $packageSums -PathType Leaf)) {
    throw "Package is missing SHA256SUMS; refusing to install."
}

$expectedHashes = @()
foreach ($line in (Get-Content -LiteralPath $packageSums -ErrorAction Stop)) {
    $parts = $line.Trim() -split '\s+', 2
    if ($parts.Count -eq 2 -and $parts[1] -eq "bin/openllmd.exe") {
        $expectedHashes += [string] $parts[0]
    }
}
if ($expectedHashes.Count -ne 1 -or $expectedHashes[0] -notmatch '^[0-9a-fA-F]{64}$') {
    throw "SHA256SUMS has no single valid bin/openllmd.exe entry; refusing to install."
}

# Hash verification is complete before the destination is created or changed.
$expectedHash = $expectedHashes[0].ToLowerInvariant()
$actualHash = (Get-FileHash -LiteralPath $packageDaemon -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "SHA256 mismatch; expected $expectedHash but computed $actualHash. No file was installed."
}

New-Item -ItemType Directory -Force -Path $resolvedDestination | Out-Null
Assert-NoReparsePointInPath $resolvedDestination
$installedPath = Join-Path -Path $resolvedDestination -ChildPath "openllmd.exe"
if (Test-Path -LiteralPath $installedPath -PathType Container) {
    throw "Installed daemon path is a directory: $installedPath"
}
if (Test-Path -LiteralPath $installedPath) {
    $installedItem = Get-Item -LiteralPath $installedPath -Force
    if (($installedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Installed daemon path is a reparse point: $installedPath"
    }
    $installedHash = (Get-FileHash -LiteralPath $installedPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($installedHash -ne $actualHash) {
        Copy-Item -LiteralPath $packageDaemon -Destination $installedPath -Force
    }
} else {
    Copy-Item -LiteralPath $packageDaemon -Destination $installedPath -Force
}

Write-Output "Installed path: $installedPath"
Write-Output "Verified SHA256: $actualHash"
