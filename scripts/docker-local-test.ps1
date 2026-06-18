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
    [switch]$SkipStart,
    [switch]$SkipBuild,
    [switch]$DownAfter
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Assert-True {
    param(
        [bool]$Condition,
        [string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Invoke-FirewallFixture {
    param(
        [string]$FixtureName,
        [string]$CorrelationId
    )

    $body = Get-Content -Raw (Join-Path $RepoRoot "tests/fixtures/$FixtureName")
    Add-Type -AssemblyName System.Net.Http
    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(15)
    $request = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::Post,
        "http://127.0.0.1:$FirewallPort/v1/chat/completions"
    )
    $request.Headers.TryAddWithoutValidation("authorization", "Bearer client-secret") | Out-Null
    $request.Headers.TryAddWithoutValidation("x-correlation-id", $CorrelationId) | Out-Null
    $request.Content = [System.Net.Http.StringContent]::new(
        $body,
        [System.Text.Encoding]::UTF8,
        "application/json"
    )

    try {
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        return @{
            Status = [int]$response.StatusCode
            Body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            Headers = @{}
        }
    } finally {
        $request.Dispose()
        $client.Dispose()
    }
}

if (-not $SkipStart) {
    $upArgs = @{
        Image = $Image
        MockImage = $MockImage
        MockBaseImage = $MockBaseImage
        Network = $Network
        FirewallName = $FirewallName
        UpstreamName = $UpstreamName
        FirewallPort = $FirewallPort
        UpstreamPort = $UpstreamPort
        DockerContext = $DockerContext
    }
    if ($SkipBuild) {
        $upArgs.SkipBuild = $true
    }

    & (Join-Path $PSScriptRoot "docker-local-up.ps1") @upArgs
}

try {
    $health = Invoke-WebRequest -Uri "http://127.0.0.1:$FirewallPort/healthz" -UseBasicParsing -TimeoutSec 5
    Assert-True ([int]$health.StatusCode -eq 200) "health check failed"

    $clean = Invoke-FirewallFixture -FixtureName "allowed_chat.json" -CorrelationId "local-clean"
    Assert-True ($clean.Status -eq 200) "clean request returned HTTP $($clean.Status): $($clean.Body)"
    Assert-True ($clean.Body -match "mock-chatcmpl-local") "clean response did not come from the mock upstream"
    Assert-True ($clean.Body -match '"upstream_authorized"\s*:\s*true') "upstream did not receive the configured bearer token"

    $blocked = Invoke-FirewallFixture -FixtureName "prompt_injection_block.json" -CorrelationId "local-blocked"
    Assert-True ($blocked.Status -eq 403) "prompt-injection request returned HTTP $($blocked.Status): $($blocked.Body)"
    Assert-True ($blocked.Body -match "prompt_injection") "blocked response did not identify the detector"

    $redacted = Invoke-FirewallFixture -FixtureName "dlp_redact_email.json" -CorrelationId "local-redacted"
    Assert-True ($redacted.Status -eq 200) "DLP redaction request returned HTTP $($redacted.Status): $($redacted.Body)"
    Assert-True ($redacted.Body -notmatch "alice@example.com") "redacted response still contained the source email"
    Assert-True ($redacted.Body -match "\[REDACTED\]") "redacted response did not include the redaction marker"

    $metrics = Invoke-WebRequest -Uri "http://127.0.0.1:$FirewallPort/metrics" -UseBasicParsing -TimeoutSec 5
    Assert-True ($metrics.Content -match "llm_firewall_requests_started_total") "metrics endpoint did not expose firewall counters"

    Write-Host "local Docker smoke test passed"
} finally {
    if ($DownAfter) {
        & (Join-Path $PSScriptRoot "docker-local-down.ps1") `
            -Network $Network `
            -FirewallName $FirewallName `
            -UpstreamName $UpstreamName `
            -DockerContext $DockerContext
    }
}
