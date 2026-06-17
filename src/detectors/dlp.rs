use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;

use crate::{
    config::{DetectorAction, DlpConfig},
    detectors::Detector,
    errors::DetectorError,
    pipeline::context::{DetectorActionTaken, RequestContext, ResponseContext},
};

#[derive(Clone)]
pub struct DlpDetector {
    rules: Vec<DlpRule>,
}

#[derive(Clone)]
struct DlpRule {
    name: String,
    regex: Regex,
    action: DetectorAction,
}

#[derive(Debug, Default)]
struct DlpOutcome {
    blocked: Vec<String>,
    redacted: Vec<String>,
    logged: Vec<String>,
}

impl DlpDetector {
    pub fn new(config: &DlpConfig) -> anyhow::Result<Self> {
        let mut rules = Vec::with_capacity(config.rules.len());
        for rule in &config.rules {
            rules.push(DlpRule {
                name: rule.name.clone(),
                regex: Regex::new(&rule.pattern)?,
                action: rule.action,
            });
        }
        Ok(Self { rules })
    }

    fn inspect_value(&self, value: &Value) -> DlpOutcome {
        let mut outcome = DlpOutcome::default();
        let mut text = String::new();
        collect_strings(value, &mut text);
        self.inspect_text(&text, &mut outcome);
        outcome
    }

    fn inspect_text(&self, text: &str, outcome: &mut DlpOutcome) {
        for rule in &self.rules {
            if rule.regex.is_match(text) {
                match rule.action {
                    DetectorAction::Block => outcome.blocked.push(rule.name.clone()),
                    DetectorAction::Redact => outcome.redacted.push(rule.name.clone()),
                    DetectorAction::LogOnly => outcome.logged.push(rule.name.clone()),
                }
            }
        }
    }

    fn redact_value(&self, value: &mut Value) {
        match value {
            Value::String(text) => {
                for rule in self
                    .rules
                    .iter()
                    .filter(|rule| rule.action == DetectorAction::Redact)
                {
                    let redacted = rule.regex.replace_all(text, "[REDACTED]").to_string();
                    *text = redacted;
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.redact_value(item);
                }
            }
            Value::Object(map) => {
                for value in map.values_mut() {
                    self.redact_value(value);
                }
            }
            _ => {}
        }
    }

    fn redact_text(&self, text: &str) -> String {
        self.rules
            .iter()
            .filter(|rule| rule.action == DetectorAction::Redact)
            .fold(text.to_string(), |current, rule| {
                rule.regex.replace_all(&current, "[REDACTED]").to_string()
            })
    }
}

#[async_trait]
impl Detector for DlpDetector {
    fn name(&self) -> &'static str {
        "dlp"
    }

    async fn inspect_request(&self, ctx: &mut RequestContext) -> Result<(), DetectorError> {
        let outcome = self.inspect_value(ctx.current_body());

        if !outcome.blocked.is_empty() {
            let reason = format!("blocked DLP rule(s): {}", outcome.blocked.join(", "));
            ctx.record(self.name(), DetectorActionTaken::Block, reason.clone());
            return Err(DetectorError::blocked(self.name(), reason));
        }

        if !outcome.redacted.is_empty() {
            let mut changed = ctx.current_body().clone();
            self.redact_value(&mut changed);
            ctx.modified_body = Some(changed);
            ctx.record(
                self.name(),
                DetectorActionTaken::Redact,
                format!("redacted DLP rule(s): {}", outcome.redacted.join(", ")),
            );
            return Ok(());
        }

        if !outcome.logged.is_empty() {
            ctx.record(
                self.name(),
                DetectorActionTaken::LogOnly,
                format!("logged DLP rule(s): {}", outcome.logged.join(", ")),
            );
            return Ok(());
        }

        ctx.record_pass(self.name());
        Ok(())
    }

    async fn inspect_response(&self, ctx: &mut ResponseContext) -> Result<(), DetectorError> {
        let mut outcome = DlpOutcome::default();
        self.inspect_text(&ctx.body_text, &mut outcome);

        if !outcome.blocked.is_empty() {
            let reason = format!("blocked DLP rule(s): {}", outcome.blocked.join(", "));
            ctx.record(self.name(), DetectorActionTaken::Block, reason.clone());
            return Err(DetectorError::blocked(self.name(), reason));
        }

        if !outcome.redacted.is_empty() {
            ctx.body_text = self.redact_text(&ctx.body_text);
            ctx.record(
                self.name(),
                DetectorActionTaken::Redact,
                format!("redacted DLP rule(s): {}", outcome.redacted.join(", ")),
            );
            return Ok(());
        }

        if !outcome.logged.is_empty() {
            ctx.record(
                self.name(),
                DetectorActionTaken::LogOnly,
                format!("logged DLP rule(s): {}", outcome.logged.join(", ")),
            );
            return Ok(());
        }

        ctx.record_pass(self.name());
        Ok(())
    }
}

fn collect_strings(value: &Value, out: &mut String) {
    match value {
        Value::String(text) => {
            out.push_str(text);
            out.push('\n');
        }
        Value::Array(items) => {
            for item in items {
                collect_strings(item, out);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                collect_strings(value, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use actix_web::http::header::HeaderMap;
    use serde_json::json;

    use super::*;
    use crate::config::{DetectorAction, DlpRuleConfig};

    #[actix_rt::test]
    async fn redacts_request_email() {
        let detector = DlpDetector::new(&DlpConfig {
            enabled: true,
            rules: vec![DlpRuleConfig {
                name: "email".into(),
                pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".into(),
                action: DetectorAction::Redact,
            }],
        })
        .unwrap();
        let mut ctx = RequestContext {
            correlation_id: "test".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: HeaderMap::new(),
            body: json!({"messages": [{"role": "user", "content": "mail me at a@example.com"}]}),
            client_ip: None,
            api_key: None,
            modified_body: None,
            detector_results: Vec::new(),
            prompt_tokens: 0,
        };

        detector.inspect_request(&mut ctx).await.unwrap();
        assert!(ctx
            .modified_body
            .unwrap()
            .to_string()
            .contains("[REDACTED]"));
    }
}
