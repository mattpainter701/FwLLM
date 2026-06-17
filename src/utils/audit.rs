use std::sync::OnceLock;

use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::{
    errors::DetectorError,
    pipeline::context::{RequestContext, ResponseContext},
};

#[derive(Clone)]
pub struct AuditLogger {
    body_chars: usize,
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    event: &'a str,
    correlation_id: &'a str,
    path: &'a str,
    method: &'a str,
    client_ip: Option<String>,
    api_key_hash: Option<String>,
    prompt_tokens: usize,
    request_detectors: &'a [crate::pipeline::context::DetectorResult],
    response_detectors: Option<&'a [crate::pipeline::context::DetectorResult]>,
    status: Option<u16>,
    request_preview: String,
    response_preview: Option<String>,
    reason: Option<String>,
}

impl AuditLogger {
    pub fn new(body_chars: usize) -> Self {
        Self { body_chars }
    }

    pub fn log_allowed(&self, req: &RequestContext, res: &ResponseContext) {
        let record = self.record("allowed", req, Some(res), None, PreviewMode::Normal);
        info!(audit = %serde_json::to_string(&record).unwrap_or_default());
    }

    pub fn log_blocked_request(&self, req: &RequestContext, err: &DetectorError) {
        let record = self.record(
            "blocked_request",
            req,
            None,
            Some(err.to_string()),
            PreviewMode::SuppressRequest,
        );
        warn!(audit = %serde_json::to_string(&record).unwrap_or_default());
    }

    pub fn log_blocked_response(
        &self,
        req: &RequestContext,
        res: &ResponseContext,
        err: &DetectorError,
    ) {
        let record = self.record(
            "blocked_response",
            req,
            Some(res),
            Some(err.to_string()),
            PreviewMode::SuppressResponse,
        );
        warn!(audit = %serde_json::to_string(&record).unwrap_or_default());
    }

    fn record<'a>(
        &self,
        event: &'a str,
        req: &'a RequestContext,
        res: Option<&'a ResponseContext>,
        reason: Option<String>,
        preview_mode: PreviewMode,
    ) -> AuditRecord<'a> {
        AuditRecord {
            event,
            correlation_id: &req.correlation_id,
            path: &req.path,
            method: &req.method,
            client_ip: req.client_ip.map(|ip| ip.to_string()),
            api_key_hash: req.api_key.as_deref().map(hash_secret),
            prompt_tokens: req.prompt_tokens,
            request_detectors: &req.detector_results,
            response_detectors: res.map(|res| res.detector_results.as_slice()),
            status: res.map(|res| res.status),
            request_preview: match preview_mode {
                PreviewMode::SuppressRequest => "[suppressed: blocked request]".to_string(),
                _ => preview(&req.current_body().to_string(), self.body_chars),
            },
            response_preview: res.map(|res| match preview_mode {
                PreviewMode::SuppressResponse => "[suppressed: blocked response]".to_string(),
                _ => preview(&res.body_text, self.body_chars),
            }),
            reason: match preview_mode {
                PreviewMode::Normal => reason.map(|reason| sanitize_for_audit(&reason)),
                PreviewMode::SuppressRequest | PreviewMode::SuppressResponse => {
                    reason.map(|_| "blocked by firewall policy".to_string())
                }
            },
        }
    }
}

#[derive(Clone, Copy)]
enum PreviewMode {
    Normal,
    SuppressRequest,
    SuppressResponse,
}

pub fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

fn preview(text: &str, max_chars: usize) -> String {
    sanitize_for_audit(text).chars().take(max_chars).collect()
}

pub(crate) fn sanitize_for_audit(text: &str) -> String {
    audit_redactors()
        .iter()
        .fold(text.to_string(), |current, redactor| {
            redactor.replace_all(&current, "[REDACTED]").to_string()
        })
}

fn audit_redactors() -> &'static [Regex] {
    static REDACTORS: OnceLock<Vec<Regex>> = OnceLock::new();
    REDACTORS.get_or_init(|| {
        [
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"\b(?:\d[ -]*?){13,19}\b",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            r"\b(?:sk|pk|rk|xox[baprs])-[-A-Za-z0-9_]{8,}\b",
            r#"(?i)("?(?:api[_-]?key|authorization|access[_-]?token|refresh[_-]?token|password|secret)"?\s*[:=]\s*)"?[^",\s}]{6,}"?"#,
        ]
        .into_iter()
        .map(|pattern| Regex::new(pattern).expect("audit redaction regex must compile"))
        .collect()
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use actix_web::http::header::HeaderMap;
    use serde_json::json;

    use super::*;
    use crate::pipeline::context::{RequestContext, ResponseContext};

    #[test]
    fn sanitizes_common_secrets_from_audit_text() {
        let text = r#"{"email":"alice@example.com","card":"4111 1111 1111 1111","api_key":"sk-live-secretvalue"}"#;
        let sanitized = sanitize_for_audit(text);

        assert!(!sanitized.contains("alice@example.com"));
        assert!(!sanitized.contains("4111 1111 1111 1111"));
        assert!(!sanitized.contains("sk-live-secretvalue"));
        assert!(sanitized.contains("[REDACTED]"));
    }

    #[test]
    fn suppresses_blocked_request_preview() {
        let logger = AuditLogger::new(2048);
        let req = RequestContext {
            correlation_id: "test".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: HeaderMap::new(),
            body: json!({"messages": [{"role": "user", "content": "custom-secret-123"}]}),
            client_ip: None,
            api_key: None,
            modified_body: None,
            detector_results: Vec::new(),
            prompt_tokens: 0,
        };

        let record = logger.record(
            "blocked_request",
            &req,
            None,
            Some("custom-secret-123".into()),
            PreviewMode::SuppressRequest,
        );

        assert_eq!(record.request_preview, "[suppressed: blocked request]");
        assert!(!record.reason.unwrap().contains("custom-secret-123"));
    }

    #[test]
    fn suppresses_blocked_response_preview() {
        let logger = AuditLogger::new(2048);
        let req = RequestContext {
            correlation_id: "test".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: HeaderMap::new(),
            body: json!({"messages": [{"role": "user", "content": "hello"}]}),
            client_ip: None,
            api_key: None,
            modified_body: None,
            detector_results: Vec::new(),
            prompt_tokens: 0,
        };
        let res = ResponseContext {
            correlation_id: "test".into(),
            status: 200,
            headers: HashMap::new(),
            body_text: "custom-secret-456".into(),
            is_stream: false,
            override_response: None,
            detector_results: Vec::new(),
        };

        let record = logger.record(
            "blocked_response",
            &req,
            Some(&res),
            Some("custom-secret-456".into()),
            PreviewMode::SuppressResponse,
        );

        assert_eq!(
            record.response_preview.as_deref(),
            Some("[suppressed: blocked response]")
        );
        assert!(!record.reason.unwrap().contains("custom-secret-456"));
    }
}
