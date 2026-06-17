use async_trait::async_trait;
use regex::Regex;

use crate::{
    config::{DetectorAction, OutputSanitizerConfig},
    detectors::Detector,
    errors::DetectorError,
    pipeline::context::{DetectorActionTaken, RequestContext, ResponseContext},
};

pub struct OutputSanitizer {
    action: DetectorAction,
    patterns: Vec<Regex>,
}

impl OutputSanitizer {
    pub fn new(config: &OutputSanitizerConfig) -> anyhow::Result<Self> {
        let patterns = [
            r"(?i)<\s*script\b[^>]*>.*?<\s*/\s*script\s*>",
            r"(?i)javascript\s*:",
            r"(?i)data\s*:\s*text/html",
            r#"(?i)\son[a-z]+\s*=\s*["'][^"']*["']"#,
            r"(?i)<\s*iframe\b[^>]*>",
        ]
        .iter()
        .map(|pattern| Regex::new(pattern))
        .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            action: config.action,
            patterns,
        })
    }

    fn has_violation(&self, text: &str) -> bool {
        self.patterns.iter().any(|pattern| pattern.is_match(text))
    }

    fn sanitize(&self, text: &str) -> String {
        self.patterns
            .iter()
            .fold(text.to_string(), |current, pattern| {
                pattern.replace_all(&current, "[REDACTED]").to_string()
            })
    }
}

#[async_trait]
impl Detector for OutputSanitizer {
    fn name(&self) -> &'static str {
        "output_sanitizer"
    }

    async fn inspect_request(&self, ctx: &mut RequestContext) -> Result<(), DetectorError> {
        ctx.record_pass(self.name());
        Ok(())
    }

    async fn inspect_response(&self, ctx: &mut ResponseContext) -> Result<(), DetectorError> {
        if !self.has_violation(&ctx.body_text) {
            ctx.record_pass(self.name());
            return Ok(());
        }

        let reason = "response contained executable HTML or JavaScript pattern".to_string();
        match self.action {
            DetectorAction::Block => {
                ctx.record(self.name(), DetectorActionTaken::Block, reason.clone());
                Err(DetectorError::blocked(self.name(), reason))
            }
            DetectorAction::Redact => {
                ctx.body_text = self.sanitize(&ctx.body_text);
                ctx.record(self.name(), DetectorActionTaken::Redact, reason);
                Ok(())
            }
            DetectorAction::LogOnly => {
                ctx.record(self.name(), DetectorActionTaken::LogOnly, reason);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::config::DetectorAction;

    #[actix_rt::test]
    async fn redacts_script_response() {
        let detector = OutputSanitizer::new(&OutputSanitizerConfig {
            enabled: true,
            action: DetectorAction::Redact,
        })
        .unwrap();
        let mut ctx = ResponseContext {
            correlation_id: "test".into(),
            status: 200,
            headers: HashMap::new(),
            body_text: "<script>alert(1)</script>".into(),
            is_stream: false,
            override_response: None,
            detector_results: Vec::new(),
        };

        detector.inspect_response(&mut ctx).await.unwrap();
        assert_eq!(ctx.body_text, "[REDACTED]");
    }
}
