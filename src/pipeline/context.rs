use std::{collections::HashMap, net::IpAddr};

use actix_web::http::header::HeaderMap;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug)]
pub struct RequestContext {
    pub correlation_id: String,
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
    pub body: Value,
    pub client_ip: Option<IpAddr>,
    pub api_key: Option<String>,
    pub modified_body: Option<Value>,
    pub detector_results: Vec<DetectorResult>,
    pub prompt_tokens: usize,
}

#[derive(Debug)]
pub struct ResponseContext {
    pub correlation_id: String,
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body_text: String,
    pub is_stream: bool,
    pub override_response: Option<String>,
    pub detector_results: Vec<DetectorResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectorResult {
    pub detector: &'static str,
    pub action: DetectorActionTaken,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorActionTaken {
    Pass,
    Block,
    Redact,
    Modify,
    LogOnly,
}

impl RequestContext {
    pub fn current_body(&self) -> &Value {
        self.modified_body.as_ref().unwrap_or(&self.body)
    }

    pub fn current_body_mut(&mut self) -> &mut Value {
        if self.modified_body.is_none() {
            self.modified_body = Some(self.body.clone());
        }
        self.modified_body
            .as_mut()
            .expect("modified body initialized")
    }

    pub fn record_pass(&mut self, detector: &'static str) {
        self.detector_results.push(DetectorResult {
            detector,
            action: DetectorActionTaken::Pass,
            reason: None,
        });
    }

    pub fn record(&mut self, detector: &'static str, action: DetectorActionTaken, reason: String) {
        self.detector_results.push(DetectorResult {
            detector,
            action,
            reason: Some(reason),
        });
    }
}

impl ResponseContext {
    pub fn record_pass(&mut self, detector: &'static str) {
        self.detector_results.push(DetectorResult {
            detector,
            action: DetectorActionTaken::Pass,
            reason: None,
        });
    }

    pub fn record(&mut self, detector: &'static str, action: DetectorActionTaken, reason: String) {
        self.detector_results.push(DetectorResult {
            detector,
            action,
            reason: Some(reason),
        });
    }
}
