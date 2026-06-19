use std::{env, fs, path::Path};

use serde::Deserialize;

use crate::errors::ConfigError;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub detectors: DetectorsConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub bind: String,
    #[serde(default = "default_allowed_paths")]
    pub allowed_paths: Vec<String>,
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,
    #[serde(default = "default_max_response_buffer")]
    pub max_response_buffer: usize,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,
    #[serde(default = "default_true")]
    pub strict_chat_validation: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub url: String,
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
    #[serde(default)]
    pub require_api_key: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DetectorsConfig {
    #[serde(default)]
    pub injection: InjectionConfig,
    #[serde(default)]
    pub dlp: DlpConfig,
    #[serde(default)]
    pub system_prompt: SystemPromptConfig,
    #[serde(default)]
    pub output_sanitizer: OutputSanitizerConfig,
    #[serde(default)]
    pub tool_call: ToolCallConfig,
    #[serde(default)]
    pub token_budget: TokenBudgetConfig,
    #[serde(default)]
    pub rate_limiter: RateLimiterConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InjectionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub action: DetectorAction,
    #[serde(default = "default_injection_patterns")]
    pub patterns: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DlpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dlp_rules")]
    pub rules: Vec<DlpRuleConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DlpRuleConfig {
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub action: DetectorAction,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OutputSanitizerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub action: DetectorAction,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SystemPromptConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: SystemPromptMode,
    #[serde(default)]
    pub prompt: String,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SystemPromptMode {
    #[default]
    Inject,
    Require,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ToolCallConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenBudgetConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_request_tokens")]
    pub max_request_tokens: usize,
    #[serde(default = "default_max_window_tokens")]
    pub max_window_tokens: usize,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimiterConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_requests_per_minute")]
    pub requests_per_minute: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_true")]
    pub json: bool,
    #[serde(default = "default_audit_body_chars")]
    pub audit_body_chars: usize,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DetectorAction {
    #[default]
    Block,
    Redact,
    LogOnly,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path)?;
        let mut config: Config = serde_yaml::from_str(&raw)?;
        config.apply_env_overrides();
        config.validate()?;
        Ok(config)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(bind) = env::var("LLMFW_BIND") {
            self.server.bind = bind;
        }
        if let Ok(url) = env::var("LLMFW_UPSTREAM_URL") {
            self.upstream.url = url;
        }
        if let Ok(api_key_env) = env::var("LLMFW_UPSTREAM_API_KEY_ENV") {
            self.upstream.api_key_env = api_key_env;
        }
        if let Ok(level) = env::var("LLMFW_LOG_LEVEL") {
            self.logging.level = level;
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.bind.trim().is_empty() {
            return Err(ConfigError::Invalid("server.bind cannot be empty".into()));
        }
        if self
            .server
            .allowed_paths
            .iter()
            .any(|path| path.trim().is_empty() || !path.starts_with('/'))
        {
            return Err(ConfigError::Invalid(
                "server.allowed_paths entries must be non-empty absolute paths".into(),
            ));
        }
        if self.server.max_body_size == 0 {
            return Err(ConfigError::Invalid(
                "server.max_body_size must be greater than zero".into(),
            ));
        }
        if self.server.max_response_buffer == 0 {
            return Err(ConfigError::Invalid(
                "server.max_response_buffer must be greater than zero".into(),
            ));
        }
        if self.server.strict_chat_validation && self.server.max_body_size > 8 * 1024 * 1024 {
            return Err(ConfigError::Invalid(
                "server.max_body_size should stay at or below 8MiB when strict chat validation is enabled".into(),
            ));
        }
        let upstream_url = url::Url::parse(&self.upstream.url)
            .map_err(|err| ConfigError::Invalid(format!("invalid upstream.url: {err}")))?;
        if upstream_url.query().is_some() || upstream_url.fragment().is_some() {
            return Err(ConfigError::Invalid(
                "upstream.url must not contain a query string or fragment".into(),
            ));
        }
        if self.upstream.require_api_key && self.upstream.api_key_env.trim().is_empty() {
            return Err(ConfigError::Invalid(
                "upstream.api_key_env cannot be empty when upstream.require_api_key is true".into(),
            ));
        }
        Ok(())
    }
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: DetectorAction::Block,
            patterns: default_injection_patterns(),
        }
    }
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules: default_dlp_rules(),
        }
    }
}

impl Default for OutputSanitizerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: DetectorAction::Redact,
        }
    }
}

impl Default for ToolCallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_tools: Vec::new(),
        }
    }
}

impl Default for SystemPromptConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: SystemPromptMode::Inject,
            prompt: String::new(),
        }
    }
}

impl Default for TokenBudgetConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_request_tokens: default_max_request_tokens(),
            max_window_tokens: default_max_window_tokens(),
            window_secs: default_window_secs(),
        }
    }
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_minute: default_requests_per_minute(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_allowed_paths() -> Vec<String> {
    vec![
        "/v1/chat/completions".to_string(),
        "/v1/responses".to_string(),
    ]
}

fn default_max_body_size() -> usize {
    1024 * 1024
}

fn default_max_response_buffer() -> usize {
    32 * 1024
}

fn default_request_timeout_secs() -> u64 {
    60
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

fn default_api_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}

fn default_max_request_tokens() -> usize {
    8192
}

fn default_max_window_tokens() -> usize {
    50_000
}

fn default_window_secs() -> u64 {
    3600
}

fn default_requests_per_minute() -> u32 {
    60
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_audit_body_chars() -> usize {
    2048
}

fn default_injection_patterns() -> Vec<String> {
    [
        "ignore previous instructions",
        "disregard all prior instructions",
        "reveal your system prompt",
        "developer mode",
        "jailbreak",
        "do anything now",
        "disable safety",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn default_dlp_rules() -> Vec<DlpRuleConfig> {
    vec![
        DlpRuleConfig {
            name: "ssn".into(),
            pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
            action: DetectorAction::Redact,
        },
        DlpRuleConfig {
            name: "credit_card".into(),
            pattern: r"\b(?:\d[ -]*?){13,19}\b".into(),
            action: DetectorAction::Block,
        },
        DlpRuleConfig {
            name: "email".into(),
            pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b".into(),
            action: DetectorAction::Redact,
        },
        DlpRuleConfig {
            name: "api_key".into(),
            pattern: r"\b(?:sk|pk|rk|xox[baprs])-[-A-Za-z0-9_]{16,}\b".into(),
            action: DetectorAction::Block,
        },
    ]
}
