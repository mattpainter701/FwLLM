use async_trait::async_trait;
use serde_json::{json, Value};

use crate::{
    config::{SystemPromptConfig, SystemPromptMode},
    detectors::Detector,
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
        body.get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|message| {
                message.get("role").and_then(Value::as_str) == Some("system")
                    && message
                        .get("content")
                        .and_then(Value::as_str)
                        .map(|content| content.contains(&self.prompt))
                        .unwrap_or(false)
            })
    }

    fn inject_prompt(&self, body: &mut Value) {
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

        if ctx
            .current_body()
            .get("messages")
            .and_then(Value::as_array)
            .is_none()
        {
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
}
