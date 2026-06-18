[CmdletBinding()]
param(
    [string]$Image = "fwllm:local",
    [string]$MockImage = "fwllm-mock-upstream:local",
    [string]$MockBaseImage = "python:3.12-alpine",
    [string]$Network = "fwllm-local",
    [string]$FirewallName = "fwllm-local-firewall",
    [string]$UpstreamName = "fwllm-local-upstream",
    [int]$FirewallPort = 8080,
    [int]$UpstreamPort = 4000,
    [string]$DockerContext = "",
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

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

function Invoke-DockerRaw {
    param([string[]]$DockerArgs)
    $args = @()
    if ($ResolvedDockerContext) {
        $args += @("--context", $ResolvedDockerContext)
    }
    $args += $DockerArgs
    & docker @args
}

function Invoke-Docker {
    param([string[]]$DockerArgs)
    Invoke-DockerRaw -DockerArgs $DockerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker $($DockerArgs -join ' ') failed"
    }
}

function Remove-ContainerIfExists {
    param([string]$Name)
    $existing = Invoke-DockerRaw -DockerArgs @("ps", "-aq", "--filter", "name=^/$Name$")
    if ($existing) {
        Invoke-Docker -DockerArgs @("rm", "-f", $Name) | Out-Null
    }
}

function Wait-HttpOk {
    param(
        [string]$Uri,
        [string]$ServiceName
    )

    for ($i = 0; $i -lt 60; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 2
            if ([int]$response.StatusCode -ge 200 -and [int]$response.StatusCode -lt 300) {
                return
            }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }

    Write-Host "logs for $ServiceName"
    Invoke-DockerRaw -DockerArgs @("logs", $ServiceName)
    throw "$ServiceName did not become healthy at $Uri"
}

function Wait-ContainerHttpOk {
    param(
        [string]$ContainerName,
        [string]$Uri,
        [string]$ServiceName
    )

    for ($i = 0; $i -lt 60; $i++) {
        Invoke-DockerRaw -DockerArgs @("exec", $ContainerName, "python", "-c", "import urllib.request; urllib.request.urlopen('$Uri', timeout=2).read()") *> $null
        if ($LASTEXITCODE -eq 0) {
            return
        }
        Start-Sleep -Milliseconds 500
    }

    Write-Host "logs for $ServiceName"
    Invoke-DockerRaw -DockerArgs @("logs", $ServiceName)
    throw "$ServiceName did not become healthy at $Uri"
}

function Test-DockerImageExists {
    param([string]$Name)
    $images = Invoke-DockerRaw -DockerArgs @("image", "ls", "--format", "{{.Repository}}:{{.Tag}}")
    return $images -contains $Name
}

if (-not $SkipBuild) {
    Invoke-Docker -DockerArgs @("build", "-t", $Image, $RepoRoot)
}

if ((-not $SkipBuild) -or (-not (Test-DockerImageExists -Name $MockImage))) {
    Invoke-Docker -DockerArgs @(
        "build",
        "-f", (Join-Path $RepoRoot "scripts/Dockerfile.mock-upstream"),
        "--build-arg", "PYTHON_IMAGE=$MockBaseImage",
        "-t", $MockImage,
        $RepoRoot
    )
}

$networks = Invoke-DockerRaw -DockerArgs @("network", "ls", "--format", "{{.Name}}")
if (-not ($networks -contains $Network)) {
    Invoke-Docker -DockerArgs @("network", "create", $Network) | Out-Null
}

Remove-ContainerIfExists -Name $FirewallName
Remove-ContainerIfExists -Name $UpstreamName

Invoke-Docker -DockerArgs @(
    "run", "-d",
    "--name", $UpstreamName,
    "--network", $Network,
    "-e", "EXPECTED_AUTH=Bearer local-upstream-secret",
    $MockImage
) | Out-Null

Wait-ContainerHttpOk -ContainerName $UpstreamName -Uri "http://127.0.0.1:4000/healthz" -ServiceName $UpstreamName

Invoke-Docker -DockerArgs @(
    "run", "-d",
    "--name", $FirewallName,
    "--network", $Network,
    "-p", "127.0.0.1:${FirewallPort}:8080",
    "-e", "LLMFW_UPSTREAM_URL=http://${UpstreamName}:4000",
    "-e", "OPENAI_API_KEY=local-upstream-secret",
    $Image
) | Out-Null

Wait-HttpOk -Uri "http://127.0.0.1:$FirewallPort/healthz" -ServiceName $FirewallName

Write-Host "firewall: http://127.0.0.1:$FirewallPort"
Write-Host "mock upstream: http://${UpstreamName}:4000 on Docker network $Network"
if ($ResolvedDockerContext) {
    Write-Host "docker context: $ResolvedDockerContext"
}
