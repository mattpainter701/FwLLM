mod config;
mod detectors;
mod errors;
mod pipeline;
mod proxy;
mod utils;

use std::sync::Arc;

use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer};
use anyhow::Context;
use config::Config;
use pipeline::Pipeline;
use proxy::handler::proxy_handler;
use proxy::upstream::UpstreamClient;
use tracing::{info, Level};
use utils::audit::AuditLogger;
use utils::metrics::Metrics;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pipeline: Arc<Pipeline>,
    pub upstream: UpstreamClient,
    pub audit: AuditLogger,
    pub metrics: Metrics,
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse()?;
    let config = Config::load(&args.config_path).context("failed to load config")?;

    init_tracing(&config);
    let pipeline = Arc::new(Pipeline::from_config(&config.detectors)?);

    if args.validate_config {
        println!("configuration OK");
        return Ok(());
    }

    let bind = config.server.bind.clone();
    let metrics_path = config.server.metrics_path.clone();
    let config = Arc::new(config);
    let upstream = UpstreamClient::new(&config.upstream, config.server.request_timeout_secs)?;
    let audit = AuditLogger::new(config.logging.audit_body_chars);
    let metrics = Metrics::default();

    let state = AppState {
        config,
        pipeline,
        upstream,
        audit,
        metrics,
    };

    info!(%bind, "starting llm-firewall");

    HttpServer::new(move || {
        let metrics_path = metrics_path.clone();
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(Logger::default())
            .route("/healthz", web::get().to(healthz))
            .route(&metrics_path, web::get().to(metrics_endpoint))
            .default_service(web::route().to(proxy_handler))
    })
    .bind(&bind)?
    .run()
    .await?;

    Ok(())
}

async fn healthz() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

async fn metrics_endpoint(state: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(state.metrics.render_prometheus())
}

fn init_tracing(config: &Config) {
    let level = config.logging.level.parse::<Level>().unwrap_or(Level::INFO);

    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env_lossy();

    if config.logging.json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }
}

struct Args {
    config_path: String,
    validate_config: bool,
}

impl Args {
    fn parse() -> anyhow::Result<Self> {
        let mut config_path = "llm-firewall.yaml".to_string();
        let mut validate_config = false;
        let mut args = std::env::args().skip(1);

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--config" | "-c" => {
                    config_path = args.next().context("--config requires a path argument")?;
                }
                "--validate-config" => validate_config = true,
                "--help" | "-h" => {
                    println!("Usage: llm-firewall [--config PATH] [--validate-config]");
                    std::process::exit(0);
                }
                other => anyhow::bail!("unknown argument: {other}"),
            }
        }

        Ok(Self {
            config_path,
            validate_config,
        })
    }
}
