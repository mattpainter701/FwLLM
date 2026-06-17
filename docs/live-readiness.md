# Live Readiness

This is the pre-live checklist for the current Rust build. It assumes the firewall is deployed as the only client-facing endpoint in front of an OpenAI-compatible upstream.

## Must Set

- Set `upstream.require_api_key: true` in production.
- Set the environment variable named by `upstream.api_key_env` on the host or container.
- Keep `server.allowed_paths` restricted to the OpenAI-compatible endpoints you actually expose.
- Keep `server.strict_chat_validation: true` unless you are explicitly proxying non-chat OpenAI endpoints.
- Keep `logging.audit_body_chars` small enough for your retention policy. Allowed-flow audit previews are sanitized, blocked request/response previews are suppressed, and all audit logs should still be treated as sensitive security telemetry.
- Put TLS termination in front of the service or add native TLS before exposing it outside a private network.

## Fail-Closed Behavior

- Missing required upstream API key returns HTTP 500 and does not call upstream.
- Requests for paths outside `server.allowed_paths` return HTTP 404 and do not call upstream.
- Invalid `/v1/chat/completions` method, content type, body, model, or messages fail before upstream.
- Prompt-injection, DLP block rules, tool violations, token limits, and rate limits all short-circuit before upstream.
- Oversized upstream responses fail with HTTP 413 instead of streaming unchecked content.

## Known Limits

- Response inspection uses accumulate-then-forward. This is safer for the current detector model but adds generation latency for streaming requests.
- Rate limits and token budgets are in-memory per process. Use one firewall instance per routing shard or add Redis before multi-replica enforcement is required.
- DLP uses configured regexes and built-in audit redactors. It is not a substitute for downstream data classification.
- Native TLS and distributed audit sinks are not implemented yet.

## Smoke Test

```bash
cargo run -- --config llm-firewall.yaml --validate-config
cargo test --locked
cargo clippy --locked --all-targets --all-features -- -D warnings
```

Then send a known-clean fixture:

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H "content-type: application/json" \
  -H "authorization: Bearer client-key" \
  --data @tests/fixtures/allowed_chat.json
```
