pub mod dlp;
pub mod injection;
pub mod output_sanitizer;
pub mod rate_limiter;
pub mod system_prompt;
pub mod token_budget;
pub mod tool_call;

use async_trait::async_trait;
use serde_json::Value;

use crate::{
    errors::DetectorError,
    pipeline::context::{RequestContext, ResponseContext},
};

#[async_trait]
pub trait Detector: Send + Sync {
    fn name(&self) -> &'static str;

    async fn inspect_request(&self, ctx: &mut RequestContext) -> Result<(), DetectorError>;

    async fn inspect_response(&self, ctx: &mut ResponseContext) -> Result<(), DetectorError>;
}

pub(crate) fn prompt_strings(body: &Value) -> Vec<String> {
    let mut strings = Vec::new();
    collect_chat_message_strings(body, &mut strings);
    collect_response_prompt_strings(body, &mut strings);
    strings
}

pub(crate) fn content_to_strings(content: &Value) -> Vec<String> {
    match content {
        Value::String(text) => vec![text.clone()],
        Value::Array(parts) => parts.iter().flat_map(content_part_to_strings).collect(),
        Value::Object(_) => content_part_to_strings(content),
        _ => Vec::new(),
    }
}

fn content_part_to_strings(part: &Value) -> Vec<String> {
    let mut strings = Vec::new();

    match part {
        Value::String(text) => strings.push(text.clone()),
        Value::Object(object) => {
            if let Some(text) = object.get("text").and_then(Value::as_str) {
                strings.push(text.to_string());
            }
            if let Some(content) = object.get("content") {
                strings.extend(content_to_strings(content));
            }
            if let Some(output) = object.get("output") {
                strings.extend(content_to_strings(output));
            }
        }
        _ => {}
    }

    strings
}

fn collect_chat_message_strings(body: &Value, out: &mut Vec<String>) {
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        for message in messages {
            if let Some(content) = message.get("content") {
                out.extend(content_to_strings(content));
            }
        }
    }
}

fn collect_response_prompt_strings(body: &Value, out: &mut Vec<String>) {
    if let Some(instructions) = body.get("instructions").and_then(Value::as_str) {
        out.push(instructions.to_string());
    }

    if let Some(input) = body.get("input") {
        collect_response_input_strings(input, out);
    }
}

fn collect_response_input_strings(input: &Value, out: &mut Vec<String>) {
    match input {
        Value::String(text) => out.push(text.clone()),
        Value::Array(items) => {
            for item in items {
                collect_response_input_item_strings(item, out);
            }
        }
        Value::Object(_) => collect_response_input_item_strings(input, out),
        _ => {}
    }
}

fn collect_response_input_item_strings(item: &Value, out: &mut Vec<String>) {
    match item {
        Value::String(text) => out.push(text.clone()),
        Value::Object(object) => {
            if let Some(content) = object.get("content") {
                out.extend(content_to_strings(content));
            }
            if let Some(output) = object.get("output") {
                out.extend(content_to_strings(output));
            }
            if let Some(text) = object.get("text").and_then(Value::as_str) {
                out.push(text.to_string());
            }
        }
        _ => {}
    }
}
