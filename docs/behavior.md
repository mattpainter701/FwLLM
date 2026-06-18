# Behavior Reference

This document captures the behavior covered by the current Rust service and its focused integration fixtures.

## Request Path

1. The firewall accepts OpenAI-compatible JSON requests on `/v1/chat/completions` and other proxied paths.
2. The request body is capped by `server.max_body_size`.
3. Only paths listed in `server.allowed_paths` are proxied upstream. The default is `/v1/chat/completions`.
4. When `server.strict_chat_validation` is enabled, `/v1/chat/completions` must be a `POST` with `application/json`, a non-empty `model`, and a non-empty `messages` array.
5. The configured request detectors run in pipeline order:
   - rate limiter
   - token budget
   - prompt injection signatures
   - DLP
   - system prompt enforcement
   - tool allow-list validation
6. If a detector blocks, the firewall returns a JSON error and does not call the upstream.
7. If a detector redacts, the modified JSON body is forwarded.
8. The client `Authorization` header is stripped. If `upstream.api_key_env` names a non-empty environment variable, that value is sent as the upstream bearer token.
9. If `upstream.require_api_key` is true and the key is missing, the request fails closed before the upstream is called.

## Response Path

1. The upstream response body is accumulated up to `server.max_response_buffer`.
2. The response detectors run after accumulation:
   - DLP
   - response tool-call validation
   - output sanitizer
3. Redaction modifies the body returned to the client.
4. Blocking returns a JSON firewall error.
5. SSE responses are inspected with the same accumulate-then-forward strategy and returned as `text/event-stream`.

## Behavior Matrix

| Scenario | Fixture or setup | Expected result |
| --- | --- | --- |
| Clean chat request | `tests/fixtures/allowed_chat.json` | Request is forwarded and upstream response is returned. |
| Client bearer token | Any forwarded request with client `Authorization` | Client token is not forwarded; configured upstream token is injected when available. |
| Missing required upstream key | `upstream.require_api_key: true` and env var unset | HTTP 500, upstream receives no request. |
| Disallowed path | Request to a path not listed in `server.allowed_paths` | HTTP 404, upstream receives no request. |
| Malformed chat payload | Empty `messages`, missing JSON content type, or wrong method | HTTP 400/405/415, upstream receives no request. |
| Prompt injection | `tests/fixtures/prompt_injection_block.json` | HTTP 403, error mentions `prompt_injection`, upstream receives no request. |
| Redactable DLP | `tests/fixtures/dlp_redact_email.json` | Request is forwarded with the email replaced by `[REDACTED]`. |
| Executable HTML in response | Upstream returns a body containing `<script>...</script>` | Response body contains `[REDACTED]` and no script tag. |

Every proxied response includes `cache-control: no-store`, `x-content-type-options: nosniff`, `x-llm-firewall: protected`, and `x-correlation-id`.

Allowed-flow audit previews are sanitized before logging. Blocked request bodies and blocked response bodies are suppressed rather than sampled.

## Local Verification

```bash
cargo test --test integration_test
```

The integration test starts the built `llm-firewall` binary, writes a temporary config, starts an in-process mock upstream, and verifies behavior through HTTP rather than calling detector internals directly.
