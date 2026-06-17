use serde_json::Value;

use crate::detectors::message_strings;

pub fn estimate_prompt_tokens(body: &Value) -> usize {
    let mut total = 0;

    if let Some(model) = body.get("model").and_then(Value::as_str) {
        total += estimate_text_tokens(model);
    }

    for message in message_strings(body) {
        total += 4;
        total += estimate_text_tokens(&message);
    }

    if let Some(max_tokens) = body.get("max_tokens").and_then(Value::as_u64) {
        total += max_tokens as usize;
    }

    total
}

fn estimate_text_tokens(text: &str) -> usize {
    let chars = text.chars().count();
    chars.div_ceil(4).max(1)
}
