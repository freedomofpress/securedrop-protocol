use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::{
    Router,
    routing::{get, post},
};
use securedrop_demo_server::Server;

use super::handlers::*;
use super::{load_fpf_sig, load_keypair};

/// In-memory newsroom state
///
/// Note: demo only, in memory only, nothing yet persisted to disk
pub(crate) type AppState = Arc<Mutex<Server>>;

pub(crate) fn start(port: u16) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("starting tokio runtime")?;
    rt.block_on(serve(port))
}

async fn serve(port: u16) -> Result<()> {
    let kp = load_keypair()?;
    let fpf_sig = load_fpf_sig()?;

    // todo: we might want to allow this?
    if fpf_sig.is_none() {
        eprintln!(
            "warning: no FPF signature stored (run `newsroom set-fpf-sig`); \
             sources will be unable to fetch newsroom keys"
        );
    }

    let state: AppState = Arc::new(Mutex::new(Server::with_newsroom_keys(kp, fpf_sig)));

    let app = Router::new()
        .route("/", get(|| async { "securedrop newsroom (demo)\n" }))
        .route("/welcome", get(get_welcome))
        .route("/newsroom/journalists/enroll", post(post_enroll))
        .route("/newsroom/journalists/keys", post(post_replenish))
        .route("/journalists/keys", get(get_journalist_ephemeral_keys))
        .route("/messages", post(post_message))
        .route("/messages/{id}", get(get_message))
        .route("/challenges", get(get_challenges))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding to {addr}"))?;
    println!("Newsroom server listening on http://{addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("install ctrl-c handler");
    println!("\nShutting down.");
}
