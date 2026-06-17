use std::time::Duration;

use actix_web::http::{header::HeaderMap, Method};
use reqwest::header::{HeaderMap as ReqwestHeaderMap, HeaderName, HeaderValue};

use crate::{config::UpstreamConfig, errors::ProxyError};

#[derive(Clone)]
pub struct UpstreamClient {
    client: reqwest::Client,
    base_url: String,
    api_key_env: String,
    require_api_key: bool,
}

impl UpstreamClient {
    pub fn new(config: &UpstreamConfig, timeout_secs: u64) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(timeout_secs))
                .pool_max_idle_per_host(32)
                .build()?,
            base_url: config.url.trim_end_matches('/').to_string(),
            api_key_env: config.api_key_env.clone(),
            require_api_key: config.require_api_key,
        })
    }

    pub async fn forward(
        &self,
        method: &Method,
        path_and_query: &str,
        headers: &HeaderMap,
        body: Vec<u8>,
    ) -> Result<reqwest::Response, ProxyError> {
        let path = if path_and_query.starts_with('/') {
            path_and_query.to_string()
        } else {
            format!("/{path_and_query}")
        };
        let url = format!("{}{}", self.base_url, path);

        let mut request = self
            .client
            .request(
                reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
                url,
            )
            .headers(copy_headers(headers))
            .body(body);

        match std::env::var(&self.api_key_env) {
            Ok(api_key) if !api_key.trim().is_empty() => {
                request = request.bearer_auth(api_key);
            }
            _ if self.require_api_key => {
                return Err(ProxyError::MissingUpstreamApiKey(self.api_key_env.clone()));
            }
            _ => {}
        }

        request.send().await.map_err(ProxyError::Upstream)
    }
}

fn copy_headers(headers: &HeaderMap) -> ReqwestHeaderMap {
    let mut copied = ReqwestHeaderMap::new();
    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "host"
                | "content-length"
                | "connection"
                | "authorization"
                | "cookie"
                | "accept-encoding"
                | "proxy-authorization"
                | "proxy-connection"
        ) {
            continue;
        }

        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            copied.insert(name, value);
        }
    }
    copied
}
