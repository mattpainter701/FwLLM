use std::{
    collections::HashMap,
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use actix_web::{
    http::StatusCode as ActixStatusCode, web, App, HttpRequest, HttpResponse, HttpServer,
};
use serde_json::{json, Value};

#[actix_rt::test]
async fn config_example_parses() {
    let raw = fs::read_to_string(repo_path("config.example.yaml")).unwrap();
    let config: serde_yaml::Value = serde_yaml::from_str(&raw).unwrap();
    assert!(config.get("server").is_some());
    assert!(config.get("upstream").is_some());
}

#[test]
fn deployment_assets_exist() {
    for path in ["Dockerfile", "llm-firewall.service", "README.md"] {
        assert!(repo_path(path).exists(), "{path} should exist");
    }
}

#[test]
fn sample_request_fixtures_are_valid_chat_payloads() {
    for fixture in [
        "allowed_chat.json",
        "prompt_injection_block.json",
        "dlp_redact_email.json",
    ] {
        let body = load_fixture(fixture);
        assert!(
            body.get("model").and_then(Value::as_str).is_some(),
            "{fixture} should set model"
        );
        assert!(
            body.get("messages")
                .and_then(Value::as_array)
                .filter(|messages| !messages.is_empty())
                .is_some(),
            "{fixture} should contain at least one message"
        );
    }
}

#[test]
fn sample_request_fixtures_are_valid_response_payloads() {
    for fixture in [
        "allowed_response.json",
        "responses_prompt_injection_block.json",
        "responses_dlp_redact_email.json",
    ] {
        let body = load_fixture(fixture);
        assert!(
            body.get("model").and_then(Value::as_str).is_some(),
            "{fixture} should set model"
        );
        assert!(
            body.get("input").is_some(),
            "{fixture} should contain response input"
        );
    }
}

#[actix_rt::test]
async fn validate_config_cli_accepts_example_config() {
    let output = Command::new(firewall_binary())
        .arg("--config")
        .arg(repo_path("config.example.yaml"))
        .arg("--validate-config")
        .output()
        .unwrap();

    assert!(output.status.success(), "validate-config should succeed");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("configuration OK"),
        "validate-config should print a success message"
    );
}

#[actix_rt::test]
async fn forwards_clean_chat_request_and_replaces_client_authorization() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "ok"},
            "finish_reason": "stop"
        }]
    })));
    let api_key_env = unique_env_name("UPSTREAM_API_KEY");
    std::env::set_var(&api_key_env, "upstream-secret");
    let firewall = start_firewall(&upstream.url, &api_key_env).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", firewall.url))
        .bearer_auth("client-secret")
        .header("accept-encoding", "gzip")
        .header("x-correlation-id", "test-clean")
        .json(&load_fixture("allowed_chat.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-llm-firewall")
            .and_then(|value| value.to_str().ok()),
        Some("protected")
    );
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("chatcmpl-test"));

    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "upstream should receive one request");
    let forwarded = &requests[0];
    assert_eq!(
        forwarded.headers.get("authorization").map(String::as_str),
        Some("Bearer upstream-secret")
    );
    assert!(
        !forwarded.headers.contains_key("accept-encoding"),
        "client compression hints should not be forwarded because response bodies must be inspected"
    );
    assert!(
        forwarded
            .headers
            .values()
            .all(|value| !value.contains("client-secret")),
        "client bearer token should not be forwarded upstream"
    );
    assert_eq!(
        forwarded.body.pointer("/messages/0/content"),
        Some(&Value::String(
            "Summarize the release notes in one sentence.".to_string()
        ))
    );

    std::env::remove_var(api_key_env);
}

#[actix_rt::test]
async fn forwards_clean_response_request_and_replaces_client_authorization() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "resp-test",
        "object": "response",
        "output": [{
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "ok"}]
        }]
    })));
    let api_key_env = unique_env_name("UPSTREAM_API_KEY");
    std::env::set_var(&api_key_env, "upstream-secret");
    let firewall = start_firewall(&upstream.url, &api_key_env).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/responses", firewall.url))
        .bearer_auth("client-secret")
        .header("accept-encoding", "gzip")
        .header("x-correlation-id", "test-response-clean")
        .json(&load_fixture("allowed_response.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("resp-test"));

    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "upstream should receive one request");
    let forwarded = &requests[0];
    assert_eq!(
        forwarded.headers.get("authorization").map(String::as_str),
        Some("Bearer upstream-secret")
    );
    assert!(
        !forwarded.headers.contains_key("accept-encoding"),
        "client compression hints should not be forwarded because response bodies must be inspected"
    );
    assert_eq!(
        forwarded.body.pointer("/input/0/content/0/text"),
        Some(&Value::String(
            "Summarize the release notes in one sentence.".to_string()
        ))
    );

    std::env::remove_var(api_key_env);
}

#[actix_rt::test]
async fn injects_required_response_instructions_when_enabled() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "resp-policy",
        "object": "response",
        "output": []
    })));
    let firewall =
        start_firewall_with_system_prompt(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/responses", firewall.url))
        .json(&load_fixture("allowed_response.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "modified request should be forwarded");
    assert_eq!(
        requests[0].body.pointer("/instructions"),
        Some(&Value::String("enterprise policy".to_string()))
    );
    assert!(
        requests[0].body.get("messages").is_none(),
        "response requests should use instructions, not chat messages"
    );
}

#[actix_rt::test]
async fn rejects_disallowed_upstream_path_before_forwarding() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "object": "list",
        "data": []
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .get(format!("{}/v1/models", firewall.url))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(
        upstream.requests().is_empty(),
        "disallowed paths must not reach upstream"
    );
}

#[actix_rt::test]
async fn rejects_malformed_chat_request_before_forwarding() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "chatcmpl-unreachable",
        "object": "chat.completion",
        "choices": []
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", firewall.url))
        .json(&json!({"model": "gpt-4o-mini", "messages": []}))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(
        upstream.requests().is_empty(),
        "invalid chat requests should not reach upstream"
    );
}

#[actix_rt::test]
async fn rejects_malformed_response_request_before_forwarding() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "resp-unreachable",
        "object": "response",
        "output": []
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/responses", firewall.url))
        .json(&json!({"model": "gpt-4o-mini"}))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(
        upstream.requests().is_empty(),
        "invalid response requests should not reach upstream"
    );
}

#[actix_rt::test]
async fn rejects_non_json_chat_request_before_forwarding() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "chatcmpl-unreachable",
        "object": "chat.completion",
        "choices": []
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", firewall.url))
        .body("{\"model\":\"gpt-4o-mini\",\"messages\":[]}")
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    assert!(
        upstream.requests().is_empty(),
        "non-json chat requests should not reach upstream"
    );
}

#[actix_rt::test]
async fn missing_required_upstream_api_key_fails_closed() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "chatcmpl-unreachable",
        "object": "chat.completion",
        "choices": []
    })));
    let api_key_env = unique_env_name("REQUIRED_KEY");
    std::env::remove_var(&api_key_env);
    let firewall = start_firewall_with_require_api_key(&upstream.url, &api_key_env, true).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", firewall.url))
        .json(&load_fixture("allowed_chat.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(
        upstream.requests().is_empty(),
        "missing required upstream key should not call upstream"
    );
}

#[actix_rt::test]
async fn blocks_prompt_injection_before_forwarding_to_upstream() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "chatcmpl-unreachable",
        "object": "chat.completion",
        "choices": []
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", firewall.url))
        .json(&load_fixture("prompt_injection_block.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let body = response.text().await.unwrap();
    assert!(body.contains("prompt_injection"));
    assert!(
        upstream.requests().is_empty(),
        "blocked requests should not reach upstream"
    );
}

#[actix_rt::test]
async fn blocks_responses_prompt_injection_before_forwarding_to_upstream() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "resp-unreachable",
        "object": "response",
        "output": []
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/responses", firewall.url))
        .json(&load_fixture("responses_prompt_injection_block.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let body = response.text().await.unwrap();
    assert!(body.contains("prompt_injection"));
    assert!(
        upstream.requests().is_empty(),
        "blocked requests should not reach upstream"
    );
}

#[actix_rt::test]
async fn redacts_dlp_matches_before_forwarding_to_upstream() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "chatcmpl-redacted",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "redacted"},
            "finish_reason": "stop"
        }]
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", firewall.url))
        .json(&load_fixture("dlp_redact_email.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "redacted request should be forwarded");
    let content = requests[0]
        .body
        .pointer("/messages/0/content")
        .and_then(Value::as_str)
        .unwrap();
    assert!(content.contains("[REDACTED]"));
    assert!(!content.contains("alice@example.com"));
}

#[actix_rt::test]
async fn redacts_responses_dlp_matches_before_forwarding_to_upstream() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "resp-redacted",
        "object": "response",
        "output": []
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/responses", firewall.url))
        .json(&load_fixture("responses_dlp_redact_email.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let requests = upstream.requests();
    assert_eq!(requests.len(), 1, "redacted request should be forwarded");
    let content = requests[0]
        .body
        .pointer("/input/0/content/0/text")
        .and_then(Value::as_str)
        .unwrap();
    assert!(content.contains("[REDACTED]"));
    assert!(!content.contains("alice@example.com"));
}

#[actix_rt::test]
async fn blocks_unapproved_responses_request_tool_before_forwarding() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "resp-unreachable",
        "object": "response",
        "output": []
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/responses", firewall.url))
        .json(&json!({
            "model": "gpt-4o-mini",
            "input": "hello",
            "tools": [{"type": "web_search_preview"}]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let body = response.text().await.unwrap();
    assert!(body.contains("tool_call"));
    assert!(
        upstream.requests().is_empty(),
        "blocked tool requests should not reach upstream"
    );
}

#[actix_rt::test]
async fn blocks_unapproved_responses_output_tool_after_upstream() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "resp-tool",
        "object": "response",
        "output": [{
            "type": "function_call",
            "name": "unsafe_tool",
            "arguments": "{}"
        }]
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/responses", firewall.url))
        .json(&load_fixture("allowed_response.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    let body = response.text().await.unwrap();
    assert!(body.contains("tool_call"));
    assert_eq!(
        upstream.requests().len(),
        1,
        "response policy should run after one upstream call"
    );
}

#[actix_rt::test]
async fn strips_stale_body_metadata_from_upstream_response() {
    let upstream = start_upstream(
        UpstreamReply::json(json!({
            "id": "chatcmpl-metadata",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop"
            }]
        }))
        .with_header("content-encoding", "gzip")
        .with_header("etag", "\"upstream-body-tag\""),
    );
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", firewall.url))
        .json(&load_fixture("allowed_chat.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(
        !response.headers().contains_key("content-encoding"),
        "firewall must not forward stale content-encoding after body inspection"
    );
    assert!(
        !response.headers().contains_key("etag"),
        "firewall must not forward stale validators after body inspection"
    );
}

#[actix_rt::test]
async fn redacts_executable_html_from_upstream_response_body() {
    let upstream = start_upstream(UpstreamReply::json(json!({
        "id": "chatcmpl-script",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": "Render <script>alert('x')</script>"},
            "finish_reason": "stop"
        }]
    })));
    let firewall = start_firewall(&upstream.url, &unique_env_name("NO_KEY")).await;

    let response = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", firewall.url))
        .json(&load_fixture("allowed_chat.json"))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("[REDACTED]"));
    assert!(!body.to_ascii_lowercase().contains("<script"));
}

fn repo_path(path: impl AsRef<std::path::Path>) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn load_fixture(name: &str) -> Value {
    let raw = fs::read_to_string(repo_path(PathBuf::from("tests/fixtures").join(name))).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn firewall_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_llm-firewall")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            repo_path(
                PathBuf::from("target")
                    .join("debug")
                    .join(format!("llm-firewall{}", std::env::consts::EXE_SUFFIX)),
            )
        })
}

async fn start_firewall(upstream_url: &str, api_key_env: &str) -> FirewallProcess {
    start_firewall_with_require_api_key(upstream_url, api_key_env, false).await
}

async fn start_firewall_with_system_prompt(
    upstream_url: &str,
    api_key_env: &str,
) -> FirewallProcess {
    start_firewall_with_options(upstream_url, api_key_env, false, Some("enterprise policy")).await
}

async fn start_firewall_with_require_api_key(
    upstream_url: &str,
    api_key_env: &str,
    require_api_key: bool,
) -> FirewallProcess {
    start_firewall_with_options(upstream_url, api_key_env, require_api_key, None).await
}

async fn start_firewall_with_options(
    upstream_url: &str,
    api_key_env: &str,
    require_api_key: bool,
    system_prompt: Option<&str>,
) -> FirewallProcess {
    let bind_port = unused_port();
    let config_path = write_test_config(
        bind_port,
        upstream_url,
        api_key_env,
        require_api_key,
        system_prompt,
    );
    let mut child = Command::new(firewall_binary())
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let url = format!("http://127.0.0.1:{bind_port}");
    let healthz = format!("{url}/healthz");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(250))
        .build()
        .unwrap();

    for _ in 0..50 {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("firewall exited before becoming healthy: {status}");
        }

        if client
            .get(&healthz)
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
        {
            return FirewallProcess {
                child,
                config_path,
                url,
            };
        }

        actix_rt::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = child.kill();
    let _ = child.wait();
    panic!("firewall did not become healthy at {healthz}");
}

fn write_test_config(
    bind_port: u16,
    upstream_url: &str,
    api_key_env: &str,
    require_api_key: bool,
    system_prompt: Option<&str>,
) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "llm-firewall-test-{}-{}.yaml",
        std::process::id(),
        unique_suffix()
    ));

    let system_prompt_yaml = system_prompt
        .map(|prompt| {
            format!(
                r#"  system_prompt:
    enabled: true
    mode: "inject"
    prompt: "{prompt}"
"#
            )
        })
        .unwrap_or_default();

    let yaml = format!(
        r#"server:
  bind: "127.0.0.1:{bind_port}"
  allowed_paths:
    - "/v1/chat/completions"
    - "/v1/responses"
  max_body_size: 1048576
  max_response_buffer: 32768
  request_timeout_secs: 5
  metrics_path: "/metrics"
  strict_chat_validation: true
upstream:
  url: "{upstream_url}"
  api_key_env: "{api_key_env}"
  require_api_key: {require_api_key}
detectors:
  injection:
    enabled: true
    action: "block"
    patterns:
      - "ignore previous instructions"
      - "disregard all prior instructions"
      - "reveal your system prompt"
      - "developer mode"
      - "jailbreak"
  dlp:
    enabled: true
    rules:
      - name: "ssn"
        pattern: '\b\d{{3}}-\d{{2}}-\d{{4}}\b'
        action: "redact"
      - name: "credit_card"
        pattern: '\b(?:\d[ -]*?){{13,19}}\b'
        action: "block"
      - name: "email"
        pattern: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{{2,}}\b'
        action: "redact"
      - name: "api_key"
        pattern: '\b(?:sk|pk|rk|xox[baprs])-[-A-Za-z0-9_]{{16,}}\b'
        action: "block"
{system_prompt_yaml}  output_sanitizer:
    enabled: true
    action: "redact"
  tool_call:
    enabled: true
    allowed_tools:
      - "get_weather"
      - "search_docs"
  token_budget:
    enabled: false
  rate_limiter:
    enabled: false
logging:
  level: "error"
  json: true
  audit_body_chars: 2048
"#
    );

    fs::write(&path, yaml).unwrap();
    path
}

fn unused_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn unique_env_name(name: &str) -> String {
    format!("LLMFW_TEST_{name}_{}", unique_suffix())
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

struct FirewallProcess {
    child: Child,
    config_path: PathBuf,
    url: String,
}

impl Drop for FirewallProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.config_path);
    }
}

#[derive(Clone)]
struct MockUpstream {
    url: String,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl MockUpstream {
    fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().unwrap().clone()
    }
}

#[derive(Clone, Debug)]
struct CapturedRequest {
    headers: HashMap<String, String>,
    body: Value,
}

#[derive(Clone)]
struct UpstreamReply {
    status: u16,
    content_type: String,
    headers: HashMap<String, String>,
    body: String,
}

impl UpstreamReply {
    fn json(body: Value) -> Self {
        Self {
            status: 200,
            content_type: "application/json".to_string(),
            headers: HashMap::new(),
            body: body.to_string(),
        }
    }

    fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }
}

#[derive(Clone)]
struct UpstreamState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    reply: UpstreamReply,
}

fn start_upstream(reply: UpstreamReply) -> MockUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let state = UpstreamState {
        requests: Arc::clone(&requests),
        reply,
    };

    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .default_service(web::route().to(capture_request))
    })
    .listen(listener)
    .unwrap()
    .run();

    actix_rt::spawn(server);

    MockUpstream {
        url: format!("http://{addr}"),
        requests,
    }
}

async fn capture_request(
    req: HttpRequest,
    body: web::Bytes,
    state: web::Data<UpstreamState>,
) -> HttpResponse {
    let headers = req
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect::<HashMap<_, _>>();
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);

    state
        .requests
        .lock()
        .unwrap()
        .push(CapturedRequest { headers, body });

    let mut response = HttpResponse::build(ActixStatusCode::from_u16(state.reply.status).unwrap());
    response.content_type(state.reply.content_type.clone());
    for (name, value) in &state.reply.headers {
        response.insert_header((name.as_str(), value.as_str()));
    }
    response.body(state.reply.body.clone())
}
