use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

#[derive(Clone, Default)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

#[derive(Default)]
struct MetricsInner {
    requests_started: AtomicU64,
    requests_allowed: AtomicU64,
    request_blocks: AtomicU64,
    response_blocks: AtomicU64,
    validation_errors: AtomicU64,
    upstream_errors: AtomicU64,
    proxy_errors: AtomicU64,
}

impl Metrics {
    pub fn request_started(&self) {
        self.inner.requests_started.fetch_add(1, Ordering::Relaxed);
    }

    pub fn request_allowed(&self) {
        self.inner.requests_allowed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn request_blocked(&self) {
        self.inner.request_blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn response_blocked(&self) {
        self.inner.response_blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn validation_error(&self) {
        self.inner.validation_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn upstream_error(&self) {
        self.inner.upstream_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn proxy_error(&self) {
        self.inner.proxy_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        format!(
            "# HELP llm_firewall_requests_started_total Total requests received\n\
             # TYPE llm_firewall_requests_started_total counter\n\
             llm_firewall_requests_started_total {}\n\
             # HELP llm_firewall_requests_allowed_total Requests allowed after inspection\n\
             # TYPE llm_firewall_requests_allowed_total counter\n\
             llm_firewall_requests_allowed_total {}\n\
             # HELP llm_firewall_request_blocks_total Requests blocked before upstream forwarding\n\
             # TYPE llm_firewall_request_blocks_total counter\n\
             llm_firewall_request_blocks_total {}\n\
             # HELP llm_firewall_response_blocks_total Upstream responses blocked after inspection\n\
             # TYPE llm_firewall_response_blocks_total counter\n\
             llm_firewall_response_blocks_total {}\n\
             # HELP llm_firewall_validation_errors_total Requests rejected by protocol/schema validation\n\
             # TYPE llm_firewall_validation_errors_total counter\n\
             llm_firewall_validation_errors_total {}\n\
             # HELP llm_firewall_upstream_errors_total Requests that failed while preparing or calling upstream\n\
             # TYPE llm_firewall_upstream_errors_total counter\n\
             llm_firewall_upstream_errors_total {}\n\
             # HELP llm_firewall_proxy_errors_total Proxy-level request/response handling errors\n\
             # TYPE llm_firewall_proxy_errors_total counter\n\
             llm_firewall_proxy_errors_total {}\n",
            self.inner.requests_started.load(Ordering::Relaxed),
            self.inner.requests_allowed.load(Ordering::Relaxed),
            self.inner.request_blocks.load(Ordering::Relaxed),
            self.inner.response_blocks.load(Ordering::Relaxed),
            self.inner.validation_errors.load(Ordering::Relaxed),
            self.inner.upstream_errors.load(Ordering::Relaxed),
            self.inner.proxy_errors.load(Ordering::Relaxed),
        )
    }
}
