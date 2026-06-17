use crate::{
    config::DetectorsConfig,
    detectors::{
        dlp::DlpDetector, injection::InjectionDetector, output_sanitizer::OutputSanitizer,
        rate_limiter::RateLimitDetector, system_prompt::SystemPromptDetector,
        token_budget::TokenBudgetDetector, tool_call::ToolCallDetector, Detector,
    },
    errors::DetectorError,
    pipeline::context::{RequestContext, ResponseContext},
};

pub struct Pipeline {
    request_detectors: Vec<Box<dyn Detector>>,
    response_detectors: Vec<Box<dyn Detector>>,
}

impl Pipeline {
    pub fn from_config(config: &DetectorsConfig) -> anyhow::Result<Self> {
        let mut request_detectors: Vec<Box<dyn Detector>> = Vec::new();
        let mut response_detectors: Vec<Box<dyn Detector>> = Vec::new();

        if config.rate_limiter.enabled {
            request_detectors.push(Box::new(RateLimitDetector::new(&config.rate_limiter)?));
        }

        if config.token_budget.enabled {
            request_detectors.push(Box::new(TokenBudgetDetector::new(&config.token_budget)));
        }

        if config.injection.enabled {
            request_detectors.push(Box::new(InjectionDetector::new(&config.injection)?));
        }

        if config.dlp.enabled {
            let detector = DlpDetector::new(&config.dlp)?;
            request_detectors.push(Box::new(detector.clone()));
            response_detectors.push(Box::new(detector));
        }

        if config.system_prompt.enabled {
            request_detectors.push(Box::new(SystemPromptDetector::new(&config.system_prompt)));
        }

        if config.tool_call.enabled {
            let detector = ToolCallDetector::new(&config.tool_call);
            request_detectors.push(Box::new(detector.clone()));
            response_detectors.push(Box::new(detector));
        }

        if config.output_sanitizer.enabled {
            response_detectors.push(Box::new(OutputSanitizer::new(&config.output_sanitizer)?));
        }

        Ok(Self {
            request_detectors,
            response_detectors,
        })
    }

    pub async fn run_request(&self, ctx: &mut RequestContext) -> Result<(), DetectorError> {
        for detector in &self.request_detectors {
            detector.inspect_request(ctx).await?;
        }
        Ok(())
    }

    pub async fn run_response(&self, ctx: &mut ResponseContext) -> Result<(), DetectorError> {
        for detector in &self.response_detectors {
            detector.inspect_response(ctx).await?;
        }
        Ok(())
    }
}
