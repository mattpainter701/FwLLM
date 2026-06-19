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

        let mut denied = names
            .into_iter()
            .filter(|name| !self.allowed_tools.contains(name))
            .collect::<Vec<_>>();
        denied.sort();
        denied.dedup();

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
        let names = response_tool_names_from_text(&ctx.body_text, ctx.is_stream);
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
                .or_else(|| tool.get("name").and_then(Value::as_str))
                .or_else(|| tool.get("type").and_then(Value::as_str))
            {
                names.push(name.to_string());
            }
        }
    }

    names
}

fn response_tool_names_from_text(body_text: &str, is_stream: bool) -> Vec<String> {
    let mut names = Vec::new();

    if is_stream {
        for value in sse_json_values(body_text) {
            collect_response_tool_names(&value, &mut names);
        }
        return names;
    }

    if let Ok(value) = serde_json::from_str::<Value>(body_text) {
        collect_response_tool_names(&value, &mut names);
    }

    names
}

fn sse_json_values(body_text: &str) -> Vec<Value> {
    body_text
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let data = line.strip_prefix("data:")?.trim();
            if data == "[DONE]" {
                return None;
            }
            serde_json::from_str::<Value>(data).ok()
        })
        .collect()
}

fn collect_response_tool_names(body: &Value, names: &mut Vec<String>) {
    if let Value::Array(items) = body {
        for item in items {
            collect_response_tool_names(item, names);
        }
        return;
    }

    collect_chat_response_tool_names(body, names);
    collect_response_output_tool_names(body, names);

    for key in ["response", "item", "delta", "data"] {
        if let Some(value) = body.get(key) {
            collect_response_tool_names(value, names);
        }
    }
}

fn collect_chat_response_tool_names(body: &Value, names: &mut Vec<String>) {
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
}

fn collect_response_output_tool_names(body: &Value, names: &mut Vec<String>) {
    if is_response_tool_item(body) {
        push_response_tool_name(body, names);
    }

    if let Some(output) = body.get("output").and_then(Value::as_array) {
        for item in output {
            collect_response_output_tool_names(item, names);
        }
    }
}

fn is_response_tool_item(item: &Value) -> bool {
    let Some(item_type) = item.get("type").and_then(Value::as_str) else {
        return false;
    };

    matches!(item_type, "function_call" | "custom_tool_call") || item_type.ends_with("_call")
}

fn push_response_tool_name(item: &Value, names: &mut Vec<String>) {
    let name = item
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| item.get("type").and_then(Value::as_str));
    if let Some(name) = name {
        names.push(name.to_string());
    }
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

    #[actix_rt::test]
    async fn blocks_unapproved_responses_request_tool() {
        let detector = ToolCallDetector::new(&ToolCallConfig {
            enabled: true,
            allowed_tools: vec!["safe_tool".into()],
        });
        let mut ctx = RequestContext {
            correlation_id: "test".into(),
            method: "POST".into(),
            path: "/v1/responses".into(),
            headers: HeaderMap::new(),
            body: json!({
                "model": "gpt-4o-mini",
                "input": "hello",
                "tools": [{"type": "web_search_preview"}]
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

    #[actix_rt::test]
    async fn blocks_unapproved_responses_output_tool() {
        let detector = ToolCallDetector::new(&ToolCallConfig {
            enabled: true,
            allowed_tools: vec!["safe_tool".into()],
        });
        let mut ctx = ResponseContext {
            correlation_id: "test".into(),
            status: 200,
            headers: std::collections::HashMap::new(),
            body_text: json!({
                "id": "resp_test",
                "object": "response",
                "output": [{
                    "type": "function_call",
                    "name": "unsafe_tool",
                    "arguments": "{}"
                }]
            })
            .to_string(),
            is_stream: false,
            override_response: None,
            detector_results: Vec::new(),
        };

        let err = detector.inspect_response(&mut ctx).await.unwrap_err();
        assert!(matches!(err, DetectorError::Blocked { .. }));
    }

    #[actix_rt::test]
    async fn blocks_unapproved_streamed_response_tool() {
        let detector = ToolCallDetector::new(&ToolCallConfig {
            enabled: true,
            allowed_tools: vec!["safe_tool".into()],
        });
        let mut ctx = ResponseContext {
            correlation_id: "test".into(),
            status: 200,
            headers: std::collections::HashMap::new(),
            body_text: concat!(
                "event: response.output_item.done\n",
                "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"name\":\"unsafe_tool\"}}\n\n",
                "data: [DONE]\n"
            )
            .to_string(),
            is_stream: true,
            override_response: None,
            detector_results: Vec::new(),
        };

        let err = detector.inspect_response(&mut ctx).await.unwrap_err();
        assert!(matches!(err, DetectorError::Blocked { .. }));
    }
}
