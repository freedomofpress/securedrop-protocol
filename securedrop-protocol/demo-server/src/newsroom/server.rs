use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use axum::{
    Router,
    routing::{get, post},
};
use securedrop_protocol_minimal::keys::NewsroomKeyPair;
use securedrop_protocol_minimal::storage::ServerMessageStore;
use securedrop_protocol_minimal::{
    Enrollment, FpfOnNewsroom, NewsroomOnJournalist, Signature, SignedKeyBundlePublic,
};

use super::handlers::*;
use super::{load_fpf_sig, load_keypair};

/// An enrolled journalist's long term enrollment together with the newsroom's
/// signature over their verifying key - together so it can be served to sources.
#[derive(Clone)]
pub(crate) struct EnrolledJournalist {
    pub(crate) enrollment: Enrollment,
    pub(crate) nr_sig: Signature<NewsroomOnJournalist>,
}

/// In-memory newsroom state
///
/// Note: demo only, in memory only, nothing yet persisted to disk
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) vk_hex: Arc<String>,
    pub(crate) newsroom_kp: Arc<NewsroomKeyPair>,
    /// FPF's signature over the newsroom verifying key
    pub(crate) fpf_sig: Option<Signature<FpfOnNewsroom>>,
    /// Enrolled journalists, keyed by long term verifying key
    pub(crate) journalists: Arc<Mutex<HashMap<String, EnrolledJournalist>>>,
    /// Stored ephemeral key bundles, keyed by journalist verifying key
    pub(crate) ephemeral_keys: Arc<Mutex<HashMap<String, Vec<SignedKeyBundlePublic>>>>,
    /// Submitted messages, keyed by server-assigned message ID
    pub(crate) messages: Arc<Mutex<ServerMessageStore>>,
}

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

    let state = AppState {
        vk_hex: Arc::new(hex::encode(kp.verifying_key().into_bytes())),
        newsroom_kp: Arc::new(kp),
        fpf_sig,
        journalists: Arc::new(Mutex::new(HashMap::new())),
        ephemeral_keys: Arc::new(Mutex::new(HashMap::new())),
        messages: Arc::new(Mutex::new(ServerMessageStore::default())),
    };

    let app = Router::new()
        .route("/", get(|| async { "securedrop newsroom (demo)\n" }))
        .route("/newsroom", get(get_newsroom))
        .route("/newsroom/keys", get(get_newsroom_keys))
        .route("/newsroom/journalists/enroll", post(post_enroll))
        .route("/newsroom/journalists/keys", post(post_replenish))
        .route("/journalists/keys", get(get_journalist_keys))
        .route("/messages", post(post_message))
        .route("/messages/:id", get(get_message).delete(delete_message))
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
