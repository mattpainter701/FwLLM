use std::collections::HashMap;

use actix_web::{
    http::{header, Method, StatusCode},
    web, HttpRequest, HttpResponse,
};
use bytes::BytesMut;
use futures_util::StreamExt;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    errors::ProxyError,
    pipeline::context::{RequestContext, ResponseContext},
    AppState,
};

pub async fn proxy_handler(
    req: HttpRequest,
    mut payload: web::Payload,
    state: web::Data<AppState>,
) -> Result<HttpResponse, ProxyError> {
    state.metrics.request_started();

    let body = match read_body(&mut payload, state.config.server.max_body_size).await {
        Ok(body) => body,
        Err(err) => {
            state.metrics.proxy_error();
            return Err(err);
        }
    };
    let correlation_id = correlation_id(&req);
    let api_key = bearer_token(req.headers());
    let path = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| req.path().to_string());

    if !is_allowed_path(req.path(), &state.config.server.allowed_paths) {
        state.metrics.validation_error();
        return Err(ProxyError::PathNotAllowed);
    }

    if state.config.server.strict_chat_validation {
        let validation = if is_chat_completions_path(req.path()) {
            validate_chat_envelope(&req, &body)
        } else if is_responses_path(req.path()) {
            validate_responses_envelope(&req, &body)
        } else {
            Ok(())
        };

        if let Err(err) = validation {
            state.metrics.validation_error();
            return Err(err);
        }
    }

    let json_body = if body.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice::<Value>(&body) {
            Ok(value) => value,
            Err(err) => {
                state.metrics.validation_error();
                return Err(ProxyError::InvalidJson(err));
            }
        }
    };

    let mut request_ctx = RequestContext {
        correlation_id: correlation_id.clone(),
        method: req.method().to_string(),
        path: path.clone(),
        headers: req.headers().clone(),
        body: json_body,
        client_ip: req.peer_addr().map(|addr| addr.ip()),
        api_key,
        modified_body: None,
        detector_results: Vec::new(),
        prompt_tokens: 0,
    };

    if let Err(err) = state.pipeline.run_request(&mut request_ctx).await {
        state.metrics.request_blocked();
        state.audit.log_blocked_request(&request_ctx, &err);
        return Err(ProxyError::Detector(err));
    }

    let outbound_body = if request_ctx.modified_body.is_some() {
        serde_json::to_vec(request_ctx.current_body())?
    } else {
        body
    };
    let upstream_response = match state
        .upstream
        .forward(req.method(), &path, req.headers(), outbound_body)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            state.metrics.upstream_error();
            return Err(err);
        }
    };

    let status = upstream_response.status();
    let headers = upstream_headers(upstream_response.headers());
    let is_stream = is_event_stream(upstream_response.headers())
        || request_ctx
            .current_body()
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);

    let body_text =
        match collect_response_body(upstream_response, state.config.server.max_response_buffer)
            .await
        {
            Ok(body_text) => body_text,
            Err(err) => {
                state.metrics.proxy_error();
                return Err(err);
            }
        };

    let mut response_ctx = ResponseContext {
        correlation_id,
        status: status.as_u16(),
        headers: headers.clone(),
        body_text,
        is_stream,
        override_response: None,
        detector_results: Vec::new(),
    };

    if let Err(err) = state.pipeline.run_response(&mut response_ctx).await {
        state.metrics.response_blocked();
        state
            .audit
            .log_blocked_response(&request_ctx, &response_ctx, &err);
        return Err(ProxyError::Detector(err));
    }

    state.metrics.request_allowed();
    state.audit.log_allowed(&request_ctx, &response_ctx);
    Ok(build_response(status, &headers, &response_ctx))
}

async fn read_body(payload: &mut web::Payload, max_size: usize) -> Result<Vec<u8>, ProxyError> {
    let mut bytes = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(|_| ProxyError::BodyTooLarge)?;
        if bytes.len() + chunk.len() > max_size {
            return Err(ProxyError::BodyTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes.to_vec())
}

async fn collect_response_body(
    response: reqwest::Response,
    max_size: usize,
) -> Result<String, ProxyError> {
    let mut stream = response.bytes_stream();
    let mut bytes = BytesMut::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len() + chunk.len() > max_size {
            return Err(ProxyError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn build_response(
    status: reqwest::StatusCode,
    headers: &HashMap<String, String>,
    response_ctx: &ResponseContext,
) -> HttpResponse {
    let status = StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = HttpResponse::build(status);

    for (name, value) in headers {
        if is_hop_by_hop(name) || is_body_metadata(name) {
            continue;
        }
        builder.insert_header((name.as_str(), value.as_str()));
    }

    if response_ctx.is_stream {
        builder.insert_header((header::CONTENT_TYPE, "text/event-stream"));
    }
    builder.insert_header(("cache-control", "no-store"));
    builder.insert_header(("x-content-type-options", "nosniff"));
    builder.insert_header(("x-llm-firewall", "protected"));
    builder.insert_header(("x-correlation-id", response_ctx.correlation_id.as_str()));

    let body = response_ctx
        .override_response
        .as_deref()
        .unwrap_or(&response_ctx.body_text);

    builder.body(body.to_owned())
}

fn upstream_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_string()))
        })
        .collect()
}

fn is_event_stream(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|content_type| content_type.starts_with("text/event-stream"))
        .unwrap_or(false)
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn correlation_id(req: &HttpRequest) -> String {
    req.headers()
        .get("x-correlation-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

fn bearer_token(headers: &actix_web::http::header::HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_string)
}

fn is_chat_completions_path(path: &str) -> bool {
    path == "/v1/chat/completions"
}

fn is_responses_path(path: &str) -> bool {
    path == "/v1/responses"
}

fn is_allowed_path(path: &str, allowed_paths: &[String]) -> bool {
    allowed_paths.is_empty() || allowed_paths.iter().any(|allowed| allowed == path)
}

fn validate_chat_envelope(req: &HttpRequest, body: &[u8]) -> Result<(), ProxyError> {
    if req.method() != Method::POST {
        return Err(ProxyError::MethodNotAllowed);
    }

    if body.is_empty() {
        return Err(ProxyError::MissingBody);
    }

    if !is_json_content_type(req.headers()) {
        return Err(ProxyError::UnsupportedContentType);
    }

    let value = serde_json::from_slice::<Value>(body)?;
    validate_chat_body(&value)
}

fn validate_responses_envelope(req: &HttpRequest, body: &[u8]) -> Result<(), ProxyError> {
    if req.method() != Method::POST {
        return Err(ProxyError::MethodNotAllowed);
    }

    if body.is_empty() {
        return Err(ProxyError::MissingBody);
    }

    if !is_json_content_type(req.headers()) {
        return Err(ProxyError::UnsupportedContentType);
    }

    let value = serde_json::from_slice::<Value>(body)?;
    validate_responses_body(&value)
}

fn is_json_content_type(headers: &actix_web::http::header::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .map(str::trim)
                .map(|media_type| media_type.eq_ignore_ascii_case("application/json"))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn validate_chat_body(body: &Value) -> Result<(), ProxyError> {
    let object = body
        .as_object()
        .ok_or_else(|| ProxyError::InvalidChatRequest("body must be a JSON object".into()))?;

    let model = object
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if model.is_empty() {
        return Err(ProxyError::InvalidChatRequest(
            "model must be a non-empty string".into(),
        ));
    }

    let messages = object
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| ProxyError::InvalidChatRequest("messages must be an array".into()))?;
    if messages.is_empty() {
        return Err(ProxyError::InvalidChatRequest(
            "messages must not be empty".into(),
        ));
    }

    for (index, message) in messages.iter().enumerate() {
        validate_message(index, message)?;
    }

    Ok(())
}

fn validate_message(index: usize, message: &Value) -> Result<(), ProxyError> {
    let object = message.as_object().ok_or_else(|| {
        ProxyError::InvalidChatRequest(format!("messages[{index}] must be an object"))
    })?;

    let role = object
        .get("role")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if role.is_empty() {
        return Err(ProxyError::InvalidChatRequest(format!(
            "messages[{index}].role must be a non-empty string"
        )));
    }

    let Some(content) = object.get("content") else {
        return Ok(());
    };

    match content {
        Value::String(_) | Value::Null => Ok(()),
        Value::Array(parts) => {
            for (part_index, part) in parts.iter().enumerate() {
                if part.as_object().is_none() {
                    return Err(ProxyError::InvalidChatRequest(format!(
                        "messages[{index}].content[{part_index}] must be an object"
                    )));
                }
            }
            Ok(())
        }
        _ => Err(ProxyError::InvalidChatRequest(format!(
            "messages[{index}].content must be a string, array, or null"
        ))),
    }
}

fn validate_responses_body(body: &Value) -> Result<(), ProxyError> {
    let object = body
        .as_object()
        .ok_or_else(|| ProxyError::InvalidResponsesRequest("body must be a JSON object".into()))?;

    let model = object
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if model.is_empty() {
        return Err(ProxyError::InvalidResponsesRequest(
            "model must be a non-empty string".into(),
        ));
    }

    let input = object
        .get("input")
        .ok_or_else(|| ProxyError::InvalidResponsesRequest("input is required".into()))?;
    validate_response_input(input)?;

    if let Some(instructions) = object.get("instructions") {
        if !matches!(instructions, Value::String(_) | Value::Null) {
            return Err(ProxyError::InvalidResponsesRequest(
                "instructions must be a string or null".into(),
            ));
        }
    }

    if let Some(tools) = object.get("tools") {
        validate_response_tools(tools)?;
    }

    Ok(())
}

fn validate_response_input(input: &Value) -> Result<(), ProxyError> {
    match input {
        Value::String(text) if !text.trim().is_empty() => Ok(()),
        Value::String(_) => Err(ProxyError::InvalidResponsesRequest(
            "input must not be an empty string".into(),
        )),
        Value::Array(items) if !items.is_empty() => {
            for (index, item) in items.iter().enumerate() {
                validate_response_input_item(index, item)?;
            }
            Ok(())
        }
        Value::Array(_) => Err(ProxyError::InvalidResponsesRequest(
            "input array must not be empty".into(),
        )),
        _ => Err(ProxyError::InvalidResponsesRequest(
            "input must be a non-empty string or array".into(),
        )),
    }
}

fn validate_response_input_item(index: usize, item: &Value) -> Result<(), ProxyError> {
    let object = item.as_object().ok_or_else(|| {
        ProxyError::InvalidResponsesRequest(format!("input[{index}] must be an object"))
    })?;

    let has_role = object
        .get("role")
        .and_then(Value::as_str)
        .map(|role| !role.trim().is_empty())
        .unwrap_or(false);
    let has_type = object
        .get("type")
        .and_then(Value::as_str)
        .map(|item_type| !item_type.trim().is_empty())
        .unwrap_or(false);
    if !has_role && !has_type {
        return Err(ProxyError::InvalidResponsesRequest(format!(
            "input[{index}] must include a non-empty role or type"
        )));
    }

    if let Some(content) = object.get("content") {
        validate_response_content(&format!("input[{index}].content"), content)?;
    }
    if let Some(output) = object.get("output") {
        validate_response_content(&format!("input[{index}].output"), output)?;
    }

    Ok(())
}

fn validate_response_content(location: &str, content: &Value) -> Result<(), ProxyError> {
    match content {
        Value::String(_) | Value::Null => Ok(()),
        Value::Array(parts) => {
            for (part_index, part) in parts.iter().enumerate() {
                let part_object = part.as_object().ok_or_else(|| {
                    ProxyError::InvalidResponsesRequest(format!(
                        "{location}[{part_index}] must be an object"
                    ))
                })?;
                if part_object
                    .get("type")
                    .is_some_and(|value| !value.is_string())
                {
                    return Err(ProxyError::InvalidResponsesRequest(format!(
                        "{location}[{part_index}].type must be a string"
                    )));
                }
                if part_object
                    .get("text")
                    .is_some_and(|value| !value.is_string())
                {
                    return Err(ProxyError::InvalidResponsesRequest(format!(
                        "{location}[{part_index}].text must be a string"
                    )));
                }
            }
            Ok(())
        }
        _ => Err(ProxyError::InvalidResponsesRequest(format!(
            "{location} must be a string, array, or null"
        ))),
    }
}

fn validate_response_tools(tools: &Value) -> Result<(), ProxyError> {
    let tools = tools
        .as_array()
        .ok_or_else(|| ProxyError::InvalidResponsesRequest("tools must be an array".into()))?;

    for (index, tool) in tools.iter().enumerate() {
        let object = tool.as_object().ok_or_else(|| {
            ProxyError::InvalidResponsesRequest(format!("tools[{index}] must be an object"))
        })?;
        if optional_non_empty_string_is_invalid(object.get("type")) {
            return Err(ProxyError::InvalidResponsesRequest(format!(
                "tools[{index}].type must be a non-empty string"
            )));
        }
        if optional_non_empty_string_is_invalid(object.get("name")) {
            return Err(ProxyError::InvalidResponsesRequest(format!(
                "tools[{index}].name must be a non-empty string"
            )));
        }
    }

    Ok(())
}

fn optional_non_empty_string_is_invalid(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(text)) => text.trim().is_empty(),
        Some(_) => true,
        None => false,
    }
}

fn is_body_metadata(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-length" | "content-encoding" | "content-md5" | "etag"
    )
}
