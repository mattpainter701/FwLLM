# LLM Firewall

**A fail-closed Rust guardrail for OpenAI-compatible LLM traffic.**

`llm-firewall` sits in front of chat completion APIs and inspects requests and responses before they touch your model provider. It is built for security teams that need a small binary, predictable behavior, JSON audit logs, and a deployment path that does not require client rewrites.

<p align="center">
  <img src="docs/assets/dual-setup-animation.svg" alt="Animated chalkboard diagram showing passthrough proxy mode and LiteLLM edge mode" width="100%">
</p>

## Why It Exists

LLM gateways are now production infrastructure. They handle user prompts, tool calls, secrets, source code, regulated data, and model responses that may be rendered directly into applications. This firewall gives that traffic a security boundary:

- Block or redact prompt injection signatures before upstream.
- Redact or block DLP matches in prompts and responses.
- Enforce mandatory system prompts.
- Restrict tool/function calls to an allow-list.
- Enforce token budgets and request rate limits.
- Strip client bearer tokens and inject the real upstream key.
- Validate `/v1/chat/completions` shape before proxying.
- Emit sanitized audit logs and Prometheus-style metrics.

## Deployment Models

FwLLM is transparent at the OpenAI-compatible API layer. It is not a packet sniffer: to inspect prompts, tool calls, and model responses, it must receive decrypted HTTP traffic. In production that normally means a DNS/load-balancer change, an endpoint policy change, or a TLS-intercepting proxy in front of it.

### 1. LiteLLM Front Door

Use this when users already call an enterprise LiteLLM endpoint. Keep the user-facing hostname stable, move LiteLLM behind FwLLM, and point FwLLM at the private LiteLLM address.

```text
before:
apps -> https://litellm.company.com -> LiteLLM

after:
apps -> https://litellm.company.com -> TLS/LB -> FwLLM -> LiteLLM private address
```

Client configuration does not change if DNS or the load balancer for `litellm.company.com` is moved to FwLLM. LiteLLM should no longer be reachable directly from user or app networks.

Example:

```yaml
upstream:
  url: "http://litellm-internal.company.local:4000"
  api_key_env: "LITELLM_MASTER_KEY"
  require_api_key: true
```

This keeps LiteLLM focused on provider routing while FwLLM owns validation, DLP, prompt-injection checks, response sanitization, audit policy, and upstream auth replacement.

### 2. Public API Gateway

Use this when users or workloads would otherwise call public model APIs directly. Publish an enterprise gateway hostname and set SDK/API policy to use it.

```text
apps -> https://llm.company.com/v1/chat/completions
     -> TLS/LB
     -> FwLLM
     -> OpenAI-compatible provider API
```

Then enforce egress:

```text
app/user networks  -> deny direct provider API egress
FwLLM/LiteLLM tier -> allow provider API egress
```

This is the cleanest way to catch public API usage without breaking TLS. Users receive a normal HTTPS API endpoint, not a raw proxy IP.

### 3. DNS Intercept For Public Hostnames

Internal DNS can point known provider hostnames at the enterprise gateway:

```text
api.openai.com -> FwLLM VIP
```

This only works for body inspection if TLS is handled correctly. Public provider certificates will not match a private gateway unless clients trust an enterprise-issued interception certificate for that hostname. Use this only for managed devices where certificate trust is controlled.

### 4. Inline Network Transit

A VMware bridge, routed hop, or transit VLAN can force packets through a VM:

```text
firewall uplink -> transit VLAN -> inline proxy VM -> core switch
```

That catches flows, but HTTPS bodies remain encrypted. Inline placement only gives FwLLM inspection visibility if TLS is terminated or intercepted before traffic reaches the detector pipeline. For VMware L2 bridge designs, the port groups usually need promiscuous mode, MAC address changes, forged transmits, and a tested bypass or HA path. Treat this as an advanced deployment, not the default.

## Traffic Control Checklist

- Put FwLLM behind a stable DNS name such as `litellm.company.com` or `llm.company.com`.
- Terminate TLS at a load balancer, reverse proxy, or sidecar that forwards HTTP to FwLLM on a private network.
- Keep LiteLLM or provider-routing services private once FwLLM is in front.
- Block direct egress from client/app networks to known model provider APIs.
- Allow provider egress only from the FwLLM or LiteLLM tier.
- Keep `/metrics` and `/healthz` on a private listener, private network, or protected load-balancer path.
- Run at least two FwLLM nodes behind a load balancer for production.

## VM Profile

Use a vendor-supported LTS Linux distribution with its stock supported kernel. Avoid custom mainline kernels unless a specific NIC, TLS, or observability requirement forces it.

Recommended device profile:

| Tier | vCPU | RAM | Disk | Network | Notes |
| --- | ---: | ---: | ---: | --- | --- |
| Lab or pilot | 2 | 4 GB | 30 GB | 1 Gbps | Local validation, demos, light traffic. |
| Production node | 4 | 8 GB | 60 GB | 1-10 Gbps | Default VM size behind a load balancer. |
| Busy node | 8 | 16 GB | 100 GB | 10 Gbps | Higher concurrency; scale horizontally before oversizing one node. |

VMware defaults:

- Use `vmxnet3` NICs.
- Use one management NIC and one service NIC for reverse-proxy deployments.
- Add separate inside/outside NICs only for inline transit designs.
- Keep audit logs off the root disk in production or ship them immediately to a log platform.
- Set `LimitNOFILE` to at least `65536` for high concurrency.
- Keep NTP, DNS, and certificate trust configured before placing the node behind production DNS.

Memory sizing is driven mostly by concurrent requests and buffering. Keep `server.max_body_size` and `server.max_response_buffer` aligned with the traffic profile instead of raising them globally.

## Install

Use either a container image or a native systemd install. Containers are simplest for repeatable deployment; systemd is simplest for small VM appliances.

### Container

Build and push the image to the registry your environment already trusts:

```bash
docker build -t registry.company.com/security/fwllm:0.1.0 .
docker push registry.company.com/security/fwllm:0.1.0
```

Run it behind a private load balancer or reverse proxy:

```bash
docker run -d \
  --name fwllm \
  --restart unless-stopped \
  -p 8080:8080 \
  -e LLMFW_UPSTREAM_URL=http://litellm-internal.company.local:4000 \
  -e OPENAI_API_KEY=replace-with-secret-manager-value \
  registry.company.com/security/fwllm:0.1.0
```

For production, inject secrets from the platform secret manager instead of shell history, and place TLS termination in front of the container.

### Native Linux Service

Build or download the `llm-firewall` binary, then install it with the provided systemd unit:

```bash
sudo useradd --system --user-group --home-dir /nonexistent llmfw
sudo install -o root -g root -m 0755 target/release/llm-firewall /usr/local/bin/llm-firewall
sudo install -d -o root -g llmfw -m 0750 /etc/llm-fw
sudo install -o root -g llmfw -m 0640 llm-firewall.yaml /etc/llm-fw/config.yaml
sudo install -o root -g root -m 0644 llm-firewall.service /etc/systemd/system/llm-firewall.service
```

Create `/etc/llm-fw/llm-firewall.env` with the upstream secret reference used by the config:

```bash
sudo install -o root -g llmfw -m 0640 /dev/null /etc/llm-fw/llm-firewall.env
sudo sh -c 'printf "%s\n" "OPENAI_API_KEY=replace-with-secret-manager-value" > /etc/llm-fw/llm-firewall.env'
```

Validate and start:

```bash
sudo -u llmfw /usr/local/bin/llm-firewall --config /etc/llm-fw/config.yaml --validate-config
sudo systemctl daemon-reload
sudo systemctl enable --now llm-firewall
sudo systemctl status llm-firewall
```

## Artifact Distribution

FwLLM does not need PyPI for deployment. It is a Rust service shipped as a single binary or a container image.

Recommended artifact options:

- Container registry: GHCR, ECR, GCR, ACR, Harbor, Nexus, Artifactory, or an internal OCI registry.
- Release binary: signed Linux `x86_64` and `aarch64` artifacts attached to internal releases.
- OS package: optional `.deb` or `.rpm` for VM appliance-style installs.

Build the Linux install archive from Windows or Linux with Docker:

```powershell
.\scripts\package-release.ps1 -Version 0.1.0
```

The package is written to `dist/` and includes the binary, runtime config, systemd unit, installer, uninstaller, and install notes.

Use PyPI only if you later ship a separate Python SDK, CLI, or helper package. The runtime service itself should not depend on a Python package repository.

## Quick Start

For local testing:

```bash
cargo run -- --config config.example.yaml
```

For Docker-based localhost testing:

```powershell
.\scripts\docker-local-test.ps1
```

Send a known-clean request:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H "content-type: application/json" \
  -H "authorization: Bearer client-key" \
  --data @tests/fixtures/allowed_chat.json
```

For production, start from [llm-firewall.yaml](llm-firewall.yaml). It fails closed by default when the upstream API key is missing:

```yaml
upstream:
  url: "http://127.0.0.1:4000"
  api_key_env: "OPENAI_API_KEY"
  require_api_key: true
server:
  bind: "0.0.0.0:8080"
  allowed_paths:
    - "/v1/chat/completions"
  strict_chat_validation: true
```

Validate before launch:

```bash
cargo run -- --config llm-firewall.yaml --validate-config
```

## Detector Pipeline

Request path:

1. Strict chat request validation.
2. Rate limiter.
3. Token budget.
4. Prompt-injection signatures.
5. DLP rules.
6. System prompt enforcement.
7. Tool allow-list validation.
8. Upstream auth replacement.

Response path:

1. Accumulate response up to `server.max_response_buffer`.
2. DLP response scan.
3. Response tool-call validation.
4. Output sanitizer.
5. Sanitized audit log and client response.

Every proxied response includes:

```text
cache-control: no-store
x-content-type-options: nosniff
x-llm-firewall: protected
x-correlation-id: <request id>
```

## Configuration

Environment overrides:

```bash
LLMFW_BIND=0.0.0.0:8080
LLMFW_UPSTREAM_URL=http://127.0.0.1:4000
LLMFW_UPSTREAM_API_KEY_ENV=OPENAI_API_KEY
LLMFW_LOG_LEVEL=info
```

Key files:

- [config.example.yaml](config.example.yaml): local demo config.
- [llm-firewall.yaml](llm-firewall.yaml): stricter default runtime config.
- [llm-firewall.service](llm-firewall.service): systemd unit with `/etc/llm-fw/llm-firewall.env`.
- [Dockerfile](Dockerfile): container build example.
- [scripts/docker-local-test.ps1](scripts/docker-local-test.ps1): localhost Docker smoke test.

## Live Readiness

Read [docs/live-readiness.md](docs/live-readiness.md) before exposing this service.

Current production posture:

- Only configured `server.allowed_paths` are proxied upstream by default.
- Missing required upstream key returns HTTP 500 and does not call upstream.
- Invalid chat method, content type, body, model, or messages fail before upstream.
- Detector blocks short-circuit before upstream.
- Audit previews are redacted independently from DLP mutations.
- Blocked request/response audit previews are suppressed rather than sampled.
- Oversized responses fail closed instead of streaming unchecked content.

Known limits:

- Streaming uses accumulate-then-forward inspection. This prioritizes security over token-by-token latency.
- Rate limits and token budgets are in-memory per process.
- Native TLS termination and distributed audit sinks are not implemented yet.

## Verification

```bash
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
```

Current coverage includes unit tests for detectors and binary-level integration tests for forwarding, auth replacement, validation rejection, fail-closed upstream key handling, prompt-injection blocking, DLP redaction, and output sanitization.

## Project Map

```text
src/
  config.rs              YAML config and env overrides
  proxy/handler.rs       HTTP ingress, validation, pipeline orchestration
  proxy/upstream.rs      upstream client and auth replacement
  pipeline/              detector chain and request/response contexts
  detectors/             injection, DLP, sanitizer, tools, budget, rate limit
  utils/audit.rs         sanitized JSON audit records
  utils/metrics.rs       Prometheus-style counters
tests/
  integration_test.rs    binary-level HTTP tests with mock upstream
```

## Docs

- [Behavior reference](docs/behavior.md)
- [Live readiness checklist](docs/live-readiness.md)
