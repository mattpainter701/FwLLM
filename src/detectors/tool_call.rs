use std::collections::HashSet;

use async_trait::async_trait;
use serde_json::Value;

use crate::{
    config::ToolCallConfig,
    detectors::Detector,
    errors::DetectorError,
    pipeline::context::{DetectorActionTaken, RequestContext, ResponseContext},
};

#[derive(Clone)]
pub struct ToolCallDetector {
    allowed_tools: HashSet<String>,
}

impl ToolCallDetector {
    pub fn new(config: &ToolCallConfig) -> Self {
        Self {
            allowed_tools: config.allowed_tools.iter().cloned().collect(),
        }
    }

    fn validate_names(&self, names: Vec<String>) -> Result<(), Vec<String>> {
        if self.allowed_tools.is_empty() {
            return Ok(());
        }

        let denied = names
            .into_iter()
            .filter(|name| !self.allowed_tools.contains(name))
            .collect::<Vec<_>>();

        if denied.is_empty() {
            Ok(())
        } else {
            Err(denied)
        }
    }
}

#[async_trait]
impl Detector for ToolCallDetector {
    fn name(&self) -> &'static str {
        "tool_call"
    }

    async fn inspect_request(&self, ctx: &mut RequestContext) -> Result<(), DetectorError> {
        let names = request_tool_names(ctx.current_body());
        match self.validate_names(names) {
            Ok(()) => {
                ctx.record_pass(self.name());
                Ok(())
            }
            Err(denied) => {
                let reason = format!("tool(s) not allowed: {}", denied.join(", "));
                ctx.record(self.name(), DetectorActionTaken::Block, reason.clone());
                Err(DetectorError::blocked(self.name(), reason))
            }
        }
    }

    async fn inspect_response(&self, ctx: &mut ResponseContext) -> Result<(), DetectorError> {
        let value = match serde_json::from_str::<Value>(&ctx.body_text) {
            Ok(value) => value,
            Err(_) => {
                ctx.record_pass(self.name());
                return Ok(());
            }
        };

        let names = response_tool_names(&value);
        match self.validate_names(names) {
            Ok(()) => {
                ctx.record_pass(self.name());
                Ok(())
            }
            Err(denied) => {
                let reason = format!("response tool(s) not allowed: {}", denied.join(", "));
                ctx.record(self.name(), DetectorActionTaken::Block, reason.clone());
                Err(DetectorError::blocked(self.name(), reason))
            }
        }
    }
}

fn request_tool_names(body: &Value) -> Vec<String> {
    let mut names = Vec::new();

    if let Some(tools) = body.get("tools").and_then(Value::as_array) {
        for tool in tools {
            if let Some(name) = tool
                .get("function")
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
            {
                names.push(name.to_string());
            }
        }
    }

    names
}

fn response_tool_names(body: &Value) -> Vec<String> {
    let mut names = Vec::new();

    if let Some(choices) = body.get("choices").and_then(Value::as_array) {
        for choice in choices {
            let Some(message) = choice.get("message") else {
                continue;
            };
            let Some(tool_calls) = message.get("tool_calls").and_then(Value::as_array) else {
                continue;
            };
            for call in tool_calls {
                if let Some(name) = call
                    .get("function")
                    .and_then(|function| function.get("name"))
                    .and_then(Value::as_str)
                {
                    names.push(name.to_string());
                }
            }
        }
    }

    names
}

#[cfg(test)]
mod tests {
    use actix_web::http::header::HeaderMap;
    use serde_json::json;

    use super::*;

    #[actix_rt::test]
    async fn blocks_unapproved_request_tool() {
        let detector = ToolCallDetector::new(&ToolCallConfig {
            enabled: true,
            allowed_tools: vec!["safe_tool".into()],
        });
        let mut ctx = RequestContext {
            correlation_id: "test".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: HeaderMap::new(),
            body: json!({
                "tools": [{
                    "type": "function",
                    "function": {"name": "unsafe_tool"}
                }]
            }),
            client_ip: None,
            api_key: None,
            modified_body: None,
            detector_results: Vec::new(),
            prompt_tokens: 0,
        };

        let err = detector.inspect_request(&mut ctx).await.unwrap_err();
        assert!(matches!(err, DetectorError::Blocked { .. }));
    }
}
