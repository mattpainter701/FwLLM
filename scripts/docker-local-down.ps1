[CmdletBinding()]
param(
    [string]$Network = "fwllm-local",
    [string]$FirewallName = "fwllm-local-firewall",
    [string]$UpstreamName = "fwllm-local-upstream",
    [string]$DockerContext = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

foreach ($name in @($FirewallName, $UpstreamName)) {
    $existing = Invoke-DockerRaw -DockerArgs @("ps", "-aq", "--filter", "name=^/$name$")
    if ($existing) {
        Invoke-Docker -DockerArgs @("rm", "-f", $name) | Out-Null
    }
}

$networks = Invoke-DockerRaw -DockerArgs @("network", "ls", "--format", "{{.Name}}")
if ($networks -contains $Network) {
    Invoke-Docker -DockerArgs @("network", "rm", $Network) | Out-Null
}

if ($ResolvedDockerContext) {
    Write-Host "local Docker stack removed from context $ResolvedDockerContext"
} else {
    Write-Host "local Docker stack removed"
}
