[CmdletBinding()]
param(
    [string]$Version = "0.1.0",
    [string]$Target = "linux-x86_64",
    [string]$DockerContext = "",
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$DistRoot = Join-Path $RepoRoot "dist"
$PackageName = "fwllm-$Version-$Target"
$PackageRoot = Join-Path $DistRoot $PackageName
$BuildImage = "fwllm-package-build:$Version"

function Resolve-DockerContext {
    param([string]$Requested)
    if ($Requested) {
        return $Requested
    }

    $contexts = & docker context ls --format "{{.Name}}"
    if ($contexts -contains "desktop-linux") {
        return "desktop-linux"
    }

    return ""
}

$ResolvedDockerContext = Resolve-DockerContext -Requested $DockerContext

function Invoke-Docker {
    param([string[]]$DockerArgs)
    $args = @()
    if ($ResolvedDockerContext) {
        $args += @("--context", $ResolvedDockerContext)
    }
    $args += $DockerArgs
    & docker @args
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($DockerArgs -join ' ') failed"
    }
}

function Invoke-DockerOutput {
    param([string[]]$DockerArgs)
    $args = @()
    if ($ResolvedDockerContext) {
        $args += @("--context", $ResolvedDockerContext)
    }
    $args += $DockerArgs
    $output = & docker @args
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($DockerArgs -join ' ') failed"
    }
    return $output
}

if (-not $SkipBuild) {
    Invoke-Docker -DockerArgs @("build", "-t", $BuildImage, $RepoRoot)
    New-Item -ItemType Directory -Force -Path (Join-Path $RepoRoot "target/release") | Out-Null
    $containerId = (Invoke-DockerOutput -DockerArgs @("create", $BuildImage) | Select-Object -Last 1).Trim()
    try {
        Invoke-Docker -DockerArgs @(
            "cp",
            "${containerId}:/usr/local/bin/llm-firewall",
            (Join-Path $RepoRoot "target/release/llm-firewall")
        )
    } finally {
        Invoke-Docker -DockerArgs @("rm", "-f", $containerId) | Out-Null
    }
}

$BinaryPath = Join-Path $RepoRoot "target/release/llm-firewall"
if (-not (Test-Path $BinaryPath)) {
    throw "missing release binary at $BinaryPath"
}

if (Test-Path $PackageRoot) {
    Remove-Item -LiteralPath $PackageRoot -Recurse -Force
}

New-Item -ItemType Directory -Force -Path `
    (Join-Path $PackageRoot "bin"), `
    (Join-Path $PackageRoot "config"), `
    (Join-Path $PackageRoot "systemd"), `
    (Join-Path $PackageRoot "install/linux") | Out-Null

Copy-Item -LiteralPath $BinaryPath -Destination (Join-Path $PackageRoot "bin/llm-firewall")
Copy-Item -LiteralPath (Join-Path $RepoRoot "llm-firewall.yaml") -Destination (Join-Path $PackageRoot "config/llm-firewall.yaml")
Copy-Item -LiteralPath (Join-Path $RepoRoot "packaging/linux/llm-firewall.env.example") -Destination (Join-Path $PackageRoot "config/llm-firewall.env.example")
Copy-Item -LiteralPath (Join-Path $RepoRoot "llm-firewall.service") -Destination (Join-Path $PackageRoot "systemd/llm-firewall.service")
Copy-Item -LiteralPath (Join-Path $RepoRoot "packaging/linux/install.sh") -Destination (Join-Path $PackageRoot "install/linux/install.sh")
Copy-Item -LiteralPath (Join-Path $RepoRoot "packaging/linux/uninstall.sh") -Destination (Join-Path $PackageRoot "install/linux/uninstall.sh")
Copy-Item -LiteralPath (Join-Path $RepoRoot "packaging/linux/README.md") -Destination (Join-Path $PackageRoot "README.md")

$manifest = @(
    "name=$PackageName",
    "version=$Version",
    "target=$Target",
    "created_utc=$((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))"
)
$manifest | Set-Content -Encoding ascii (Join-Path $PackageRoot "manifest.txt")

$tarPath = Join-Path $DistRoot "$PackageName.tar.gz"
$zipPath = Join-Path $DistRoot "$PackageName.zip"
$checksumsPath = Join-Path $DistRoot "$PackageName-SHA256SUMS.txt"
if (Test-Path $tarPath) {
    Remove-Item -LiteralPath $tarPath -Force
}
if (Test-Path $zipPath) {
    Remove-Item -LiteralPath $zipPath -Force
}
if (Test-Path $checksumsPath) {
    Remove-Item -LiteralPath $checksumsPath -Force
}

tar -czf $tarPath -C $DistRoot $PackageName
Compress-Archive -Path (Join-Path $PackageRoot "*") -DestinationPath $zipPath -Force

$checksumLines = foreach ($artifact in @($tarPath, $zipPath)) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash.ToLowerInvariant()
    "$hash  $(Split-Path -Leaf $artifact)"
}
$checksumLines | Set-Content -Encoding ascii $checksumsPath

Write-Host "created $tarPath"
Write-Host "created $zipPath"
Write-Host "created $checksumsPath"
