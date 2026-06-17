pub mod dlp;
pub mod injection;
pub mod output_sanitizer;
pub mod rate_limiter;
pub mod system_prompt;
pub mod token_budget;
pub mod tool_call;

use async_trait::async_trait;

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

pub(crate) fn message_strings(body: &serde_json::Value) -> Vec<String> {
    body.get("messages")
        .and_then(|messages| messages.as_array())
        .map(|messages| {
            messages
                .iter()
                .flat_map(|message| {
                    message
                        .get("content")
                        .map(content_to_strings)
                        .unwrap_or_default()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn content_to_strings(content: &serde_json::Value) -> Vec<String> {
    match content {
        serde_json::Value::String(text) => vec![text.clone()],
        serde_json::Value::Array(parts) => parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(|text| text.as_str())
                    .map(str::to_string)
            })
            .collect(),
        _ => Vec::new(),
    }
}
