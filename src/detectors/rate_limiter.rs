use std::{num::NonZeroU32, sync::Arc};

use async_trait::async_trait;
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

use crate::{
    config::RateLimiterConfig,
    detectors::Detector,
    errors::DetectorError,
    pipeline::context::{DetectorActionTaken, RequestContext, ResponseContext},
};

pub struct RateLimitDetector {
    limiter: Arc<DefaultKeyedRateLimiter<String>>,
}

impl RateLimitDetector {
    pub fn new(config: &RateLimiterConfig) -> anyhow::Result<Self> {
        let per_minute = NonZeroU32::new(config.requests_per_minute.max(1))
            .expect("requests_per_minute is clamped to non-zero");
        Ok(Self {
            limiter: Arc::new(RateLimiter::keyed(Quota::per_minute(per_minute))),
        })
    }

    fn principal(ctx: &RequestContext) -> String {
        ctx.api_key
            .as_deref()
            .map(crate::utils::audit::hash_secret)
            .or_else(|| ctx.client_ip.map(|ip| ip.to_string()))
            .unwrap_or_else(|| "anonymous".to_string())
    }
}

#[async_trait]
impl Detector for RateLimitDetector {
    fn name(&self) -> &'static str {
        "rate_limiter"
    }

    async fn inspect_request(&self, ctx: &mut RequestContext) -> Result<(), DetectorError> {
        let principal = Self::principal(ctx);
        match self.limiter.check_key(&principal) {
            Ok(()) => {
                ctx.record_pass(self.name());
                Ok(())
            }
            Err(_) => {
                let reason = "request rate limit exceeded".to_string();
                ctx.record(self.name(), DetectorActionTaken::Block, reason.clone());
                Err(DetectorError::rate_limited(self.name(), reason))
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
    async fn rate_limits_same_principal() {
        let detector = RateLimitDetector::new(&RateLimiterConfig {
            enabled: true,
            requests_per_minute: 1,
        })
        .unwrap();

        let mut first = ctx_with_key("sk-test");
        detector.inspect_request(&mut first).await.unwrap();

        let mut second = ctx_with_key("sk-test");
        let err = detector.inspect_request(&mut second).await.unwrap_err();
        assert!(matches!(err, DetectorError::Blocked { .. }));
    }

    fn ctx_with_key(api_key: &str) -> RequestContext {
        RequestContext {
            correlation_id: "test".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: HeaderMap::new(),
            body: json!({"messages": [{"role": "user", "content": "hello"}]}),
            client_ip: None,
            api_key: Some(api_key.into()),
            modified_body: None,
            detector_results: Vec::new(),
            prompt_tokens: 0,
        }
    }
}
