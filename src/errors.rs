use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Error)]
pub enum DetectorError {
    #[error("blocked by {detector}: {reason}")]
    Blocked {
        detector: &'static str,
        reason: String,
        status: StatusCode,
    },
    #[error("{detector} failed: {reason}")]
    Failed {
        detector: &'static str,
        reason: String,
    },
}

impl DetectorError {
    pub fn blocked(detector: &'static str, reason: impl Into<String>) -> Self {
        Self::Blocked {
            detector,
            reason: reason.into(),
            status: StatusCode::FORBIDDEN,
        }
    }

    pub fn rate_limited(detector: &'static str, reason: impl Into<String>) -> Self {
        Self::Blocked {
            detector,
            reason: reason.into(),
            status: StatusCode::TOO_MANY_REQUESTS,
        }
    }

    pub fn failed(detector: &'static str, reason: impl Into<String>) -> Self {
        Self::Failed {
            detector,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("request body is too large")]
    BodyTooLarge,
    #[error("endpoint is not allowed by firewall policy")]
    PathNotAllowed,
    #[error("method not allowed for this endpoint")]
    MethodNotAllowed,
    #[error("content-type must be application/json")]
    UnsupportedContentType,
    #[error("request body is required")]
    MissingBody,
    #[error("invalid OpenAI chat completion request: {0}")]
    InvalidChatRequest(String),
    #[error("invalid OpenAI responses request: {0}")]
    InvalidResponsesRequest(String),
    #[error("invalid JSON request body: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("detector error: {0}")]
    Detector(#[from] DetectorError),
    #[error("upstream API key is required but environment variable {0} is unset or empty")]
    MissingUpstreamApiKey(String),
    #[error("upstream request failed: {0}")]
    Upstream(#[from] reqwest::Error),
    #[error("upstream response exceeded max_response_buffer")]
    ResponseTooLarge,
}

impl ResponseError for ProxyError {
    fn status_code(&self) -> StatusCode {
        match self {
            ProxyError::BodyTooLarge | ProxyError::ResponseTooLarge => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            ProxyError::PathNotAllowed => StatusCode::NOT_FOUND,
            ProxyError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ProxyError::UnsupportedContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ProxyError::MissingBody
            | ProxyError::InvalidChatRequest(_)
            | ProxyError::InvalidResponsesRequest(_)
            | ProxyError::InvalidJson(_) => StatusCode::BAD_REQUEST,
            ProxyError::Detector(DetectorError::Blocked { status, .. }) => *status,
            ProxyError::Detector(DetectorError::Failed { .. }) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::MissingUpstreamApiKey(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let message = match self {
            ProxyError::Detector(DetectorError::Blocked {
                detector, reason, ..
            }) => format!("Blocked by firewall detector {detector}: {reason}"),
            ProxyError::MissingUpstreamApiKey(_) => {
                "upstream authentication is not configured".to_string()
            }
            ProxyError::Upstream(_) => "upstream request failed".to_string(),
            other => other.to_string(),
        };

        HttpResponse::build(self.status_code())
            .insert_header(("cache-control", "no-store"))
            .insert_header(("x-content-type-options", "nosniff"))
            .json(json!({
                "error": {
                    "message": message,
                    "type": "llm_firewall_error"
                }
            }))
    }
}
