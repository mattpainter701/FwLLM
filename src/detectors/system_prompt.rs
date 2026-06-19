use async_trait::async_trait;
use serde_json::{json, Value};

use crate::{
    config::{SystemPromptConfig, SystemPromptMode},
    detectors::{content_to_strings, Detector},
    errors::DetectorError,
    pipeline::context::{DetectorActionTaken, RequestContext, ResponseContext},
};

pub struct SystemPromptDetector {
    mode: SystemPromptMode,
    prompt: String,
}

impl SystemPromptDetector {
    pub fn new(config: &SystemPromptConfig) -> Self {
        Self {
            mode: config.mode,
            prompt: config.prompt.clone(),
        }
    }

    fn has_required_prompt(&self, body: &Value) -> bool {
        self.instructions_contain_prompt(body)
            || self.chat_messages_contain_prompt(body)
            || self.response_input_contains_prompt(body)
    }

    fn inject_prompt(&self, body: &mut Value) {
        if body.get("messages").and_then(Value::as_array).is_some() {
            self.inject_chat_prompt(body);
            return;
        }

        if body.get("input").is_some() {
            self.inject_response_prompt(body);
        }
    }

    fn inject_chat_prompt(&self, body: &mut Value) {
        let prompt = json!({
            "role": "system",
            "content": self.prompt
        });

        match body.get_mut("messages").and_then(Value::as_array_mut) {
            Some(messages) => messages.insert(0, prompt),
            None => {
                body["messages"] = Value::Array(vec![prompt]);
            }
        }
    }

    fn inject_response_prompt(&self, body: &mut Value) {
        match body.get_mut("instructions") {
            Some(Value::String(existing)) if existing.contains(&self.prompt) => {}
            Some(Value::String(existing)) if existing.trim().is_empty() => {
                *existing = self.prompt.clone();
            }
            Some(Value::String(existing)) => {
                *existing = format!("{}\n\n{}", self.prompt, existing);
            }
            _ => {
                body["instructions"] = Value::String(self.prompt.clone());
            }
        }
    }

    fn has_prompt_surface(&self, body: &Value) -> bool {
        body.get("messages").and_then(Value::as_array).is_some() || body.get("input").is_some()
    }

    fn instructions_contain_prompt(&self, body: &Value) -> bool {
        body.get("instructions")
            .and_then(Value::as_str)
            .map(|instructions| instructions.contains(&self.prompt))
            .unwrap_or(false)
    }

    fn chat_messages_contain_prompt(&self, body: &Value) -> bool {
        body.get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|message| self.policy_message_contains_prompt(message))
    }

    fn response_input_contains_prompt(&self, body: &Value) -> bool {
        let Some(input) = body.get("input") else {
            return false;
        };

        match input {
            Value::Array(items) => items
                .iter()
                .any(|item| self.policy_message_contains_prompt(item)),
            Value::Object(_) => self.policy_message_contains_prompt(input),
            _ => false,
        }
    }

    fn policy_message_contains_prompt(&self, item: &Value) -> bool {
        let Some(role) = item.get("role").and_then(Value::as_str) else {
            return false;
        };
        if !matches!(role, "system" | "developer") {
            return false;
        }

        item.get("content")
            .map(content_to_strings)
            .unwrap_or_default()
            .iter()
            .any(|content| content.contains(&self.prompt))
    }
}

#[async_trait]
impl Detector for SystemPromptDetector {
    fn name(&self) -> &'static str {
        "system_prompt"
    }

    async fn inspect_request(&self, ctx: &mut RequestContext) -> Result<(), DetectorError> {
        if self.prompt.trim().is_empty() {
            ctx.record_pass(self.name());
            return Ok(());
        }

        if !self.has_prompt_surface(ctx.current_body()) {
            ctx.record_pass(self.name());
            return Ok(());
        }

        if self.has_required_prompt(ctx.current_body()) {
            ctx.record_pass(self.name());
            return Ok(());
        }

        match self.mode {
            SystemPromptMode::Inject => {
                let mut changed = ctx.current_body().clone();
                self.inject_prompt(&mut changed);
                ctx.modified_body = Some(changed);
                ctx.record(
                    self.name(),
                    DetectorActionTaken::Modify,
                    "mandatory system prompt injected".to_string(),
                );
                Ok(())
            }
            SystemPromptMode::Require => {
                let reason = "mandatory system prompt missing".to_string();
                ctx.record(self.name(), DetectorActionTaken::Block, reason.clone());
                Err(DetectorError::blocked(self.name(), reason))
            }
        }
    }

    async fn inspect_response(&self, ctx: &mut ResponseContext) -> Result<(), DetectorError> {
        ctx.record_pass(self.name());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use actix_web::http::header::HeaderMap;
    use serde_json::json;

    use super::*;

    #[actix_rt::test]
    async fn injects_required_system_prompt() {
        let detector = SystemPromptDetector::new(&SystemPromptConfig {
            enabled: true,
            mode: SystemPromptMode::Inject,
            prompt: "enterprise policy".into(),
        });
        let mut ctx = RequestContext {
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

        detector.inspect_request(&mut ctx).await.unwrap();
        let body = ctx.modified_body.unwrap();
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "enterprise policy");
    }

    #[actix_rt::test]
    async fn injects_required_response_instructions() {
        let detector = SystemPromptDetector::new(&SystemPromptConfig {
            enabled: true,
            mode: SystemPromptMode::Inject,
            prompt: "enterprise policy".into(),
        });
        let mut ctx = RequestContext {
            correlation_id: "test".into(),
            method: "POST".into(),
            path: "/v1/responses".into(),
            headers: HeaderMap::new(),
            body: json!({
                "model": "gpt-4o-mini",
                "input": [{
                    "role": "user",
                    "content": [{"type": "input_text", "text": "hello"}]
                }],
                "instructions": "answer briefly"
            }),
            client_ip: None,
            api_key: None,
            modified_body: None,
            detector_results: Vec::new(),
            prompt_tokens: 0,
        };

        detector.inspect_request(&mut ctx).await.unwrap();
        let body = ctx.modified_body.unwrap();
        assert_eq!(
            body["instructions"],
            Value::String("enterprise policy\n\nanswer briefly".to_string())
        );
        assert!(body.get("messages").is_none());
    }
}
