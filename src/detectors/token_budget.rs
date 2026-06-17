use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;

use crate::{
    config::TokenBudgetConfig,
    detectors::Detector,
    errors::DetectorError,
    pipeline::context::{DetectorActionTaken, RequestContext, ResponseContext},
};

pub struct TokenBudgetDetector {
    max_request_tokens: usize,
    max_window_tokens: usize,
    window: Duration,
    usage: DashMap<String, UsageWindow>,
}

#[derive(Clone)]
struct UsageWindow {
    start: Instant,
    tokens: usize,
}

impl TokenBudgetDetector {
    pub fn new(config: &TokenBudgetConfig) -> Self {
        Self {
            max_request_tokens: config.max_request_tokens,
            max_window_tokens: config.max_window_tokens,
            window: Duration::from_secs(config.window_secs),
            usage: DashMap::new(),
        }
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
impl Detector for TokenBudgetDetector {
    fn name(&self) -> &'static str {
        "token_budget"
    }

    async fn inspect_request(&self, ctx: &mut RequestContext) -> Result<(), DetectorError> {
        let tokens = crate::utils::token_counter::estimate_prompt_tokens(ctx.current_body());
        ctx.prompt_tokens = tokens;

        if tokens > self.max_request_tokens {
            let reason = format!(
                "request used {tokens} estimated tokens, limit is {}",
                self.max_request_tokens
            );
            ctx.record(self.name(), DetectorActionTaken::Block, reason.clone());
            return Err(DetectorError::blocked(self.name(), reason));
        }

        let principal = Self::principal(ctx);
        let now = Instant::now();
        let mut entry = self.usage.entry(principal).or_insert(UsageWindow {
            start: now,
            tokens: 0,
        });

        if now.duration_since(entry.start) > self.window {
            entry.start = now;
            entry.tokens = 0;
        }

        if entry.tokens + tokens > self.max_window_tokens {
            let reason = format!(
                "token window would use {} estimated tokens, limit is {}",
                entry.tokens + tokens,
                self.max_window_tokens
            );
            ctx.record(self.name(), DetectorActionTaken::Block, reason.clone());
            return Err(DetectorError::blocked(self.name(), reason));
        }

        entry.tokens += tokens;
        ctx.record_pass(self.name());
        Ok(())
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
    async fn blocks_request_over_token_limit() {
        let detector = TokenBudgetDetector::new(&TokenBudgetConfig {
            enabled: true,
            max_request_tokens: 1,
            max_window_tokens: 100,
            window_secs: 60,
        });
        let mut ctx = RequestContext {
            correlation_id: "test".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: HeaderMap::new(),
            body: json!({"messages": [{"role": "user", "content": "this request is over the small limit"}]}),
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
