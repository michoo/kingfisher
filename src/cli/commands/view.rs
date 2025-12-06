use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, StatusCode, Uri},
    response::Response,
    routing::get,
    Router,
};
use clap::ValueHint;
use include_dir::{include_dir, Dir};
use tokio::net::TcpListener;
use tracing::info;

const DEFAULT_PORT: u16 = 7890;
static VIEWER_ASSETS: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/docs/access-map-viewer");

/// View a Kingfisher access-map report locally.
#[derive(clap::Args, Debug)]
pub struct ViewArgs {
    /// Path to a JSON or JSONL access-map report to load automatically
    #[arg(value_name = "REPORT", value_hint = ValueHint::FilePath)]
    pub report: Option<PathBuf>,

    /// Local port for the embedded viewer (default 7890)
    #[arg(long, default_value_t = DEFAULT_PORT)]
    pub port: u16,
}

#[derive(Clone)]
struct AppState {
    report: Option<Vec<u8>>,
}

/// Run the `kingfisher view` subcommand.
pub async fn run(args: ViewArgs) -> Result<()> {
    let report = if let Some(path) = args.report.as_ref() {
        let expanded_path = expand_tilde(path)?;
        let ext = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_ascii_lowercase())
            .unwrap_or_default();

        if ext != "json" && ext != "jsonl" {
            return Err(anyhow!("Report must be a JSON or JSONL file (got extension: {})", ext));
        }

        Some(
            tokio::fs::read(&expanded_path)
                .await
                .with_context(|| format!("Failed to read report at {}", expanded_path.display()))?,
        )
    } else {
        None
    };

    let listener =
        TcpListener::bind(("127.0.0.1", args.port)).await.map_err(|err| match err.kind() {
            std::io::ErrorKind::AddrInUse => anyhow!(
                "Port {} is already in use. Re-run with --port <PORT> to choose a different port.",
                args.port
            ),
            _ => err.into(),
        })?;

    let address: SocketAddr =
        listener.local_addr().context("Failed to read local listener address")?;

    info!(%address, "Starting access-map viewer");
    eprintln!(
        "Serving access-map viewer at http://{}:{} (Ctrl+C to stop)",
        address.ip(),
        address.port()
    );

    let state = Arc::new(AppState { report });

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/report", get(serve_report))
        .route("/favicon.ico", get(serve_favicon))
        .fallback(get(serve_asset))
        .with_state(state);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_index() -> Response {
    serve_asset_at("index.html").unwrap_or_else(not_found)
}

async fn serve_favicon() -> Response {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Body::empty())
        .map(apply_security_headers)
        .unwrap_or_else(|_| internal_error())
}

async fn serve_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        return serve_index().await;
    }
    if !is_safe_path(path) {
        return not_found();
    }

    serve_asset_at(path).unwrap_or_else(not_found)
}

async fn serve_report(State(state): State<Arc<AppState>>) -> Response {
    if let Some(report) = &state.report {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, content_type_for("report.json"))
            .body(Body::from(report.clone()))
            .map(apply_security_headers)
            .unwrap_or_else(|_| internal_error());
    }

    not_found()
}

fn serve_asset_at(path: &str) -> Option<Response> {
    let file = VIEWER_ASSETS.get_file(path)?;
    let body = Body::from(file.contents().to_vec());
    let content_type = content_type_for(path);

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(body)
        .map(apply_security_headers)
        .ok()
}

fn content_type_for(path: &str) -> HeaderValue {
    if let Some(ext) = path.rsplit('.').next() {
        let mime = match ext {
            "html" => "text/html; charset=utf-8",
            "js" => "application/javascript; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "json" | "jsonl" => "application/json; charset=utf-8",
            _ => "application/octet-stream",
        };
        return HeaderValue::from_static(mime);
    }

    HeaderValue::from_static("application/octet-stream")
}

fn is_safe_path(path: &str) -> bool {
    let candidate = std::path::Path::new(path);
    candidate.components().all(|comp| matches!(comp, std::path::Component::Normal(_)))
}

fn not_found() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("Not found"))
        .map(apply_security_headers)
        .unwrap_or_else(|_| internal_error())
}

fn internal_error() -> Response {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from("Internal server error"))
        .map(apply_security_headers)
        .unwrap()
}

fn apply_security_headers(response: Response) -> Response {
    let mut response = response;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'",
        ),
    );
    response
}

fn expand_tilde(path: &Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if path_str == "~" || path_str.starts_with("~/") {
        let home = std::env::var("HOME")
            .context("Could not resolve home directory for tilde-expanded path")?;
        let trimmed = path_str.trim_start_matches("~/");
        return Ok(PathBuf::from(home).join(trimmed));
    }

    Ok(path.to_path_buf())
}
