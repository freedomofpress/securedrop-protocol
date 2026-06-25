use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use axum::http::StatusCode;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use rand_core::{OsRng, TryRngCore};
use securedrop_protocol_minimal::keys::NewsroomKeyPair;
use securedrop_protocol_minimal::wire::setup::{
    JournalistEphemeralKeyRequest, JournalistEphemeralKeyResponse, JournalistSetupRequest,
    JournalistSetupResponse,
};
use securedrop_protocol_minimal::{
    Enrollment, FpfOnNewsroom, Signature, SignedKeyBundlePublic, VerifyingKey,
};
use serde::Serialize;

use crate::state::{data_dir, write_secret};

/// In-memory newsroom state
///
/// Note: demo only, in memory only, nothing yet persisted to disk
#[derive(Clone)]
struct AppState {
    vk_hex: Arc<String>,
    newsroom_kp: Arc<NewsroomKeyPair>,
    /// Enrolled journalists, keyed by long term verifying key
    journalists: Arc<Mutex<HashMap<String, Enrollment>>>,
    /// Stored ephemeral key bundles, keyed by journalist verifying key
    ephemeral_keys: Arc<Mutex<HashMap<String, Vec<SignedKeyBundlePublic>>>>,
}

#[derive(Serialize)]
struct NewsroomInfo {
    verifying_key: String,
}

pub fn init(force: bool) -> Result<()> {
    let path = key_path()?;
    if path.exists() && !force {
        bail!(
            "a newsroom key already exists at {}\nuse `newsroom init --force` to overwrite it",
            path.display()
        );
    }

    let kp = NewsroomKeyPair::new(OsRng.unwrap_err()).context("generating newsroom keypair")?;
    let seed = kp.as_bytes();
    let vk = kp.verifying_key().into_bytes();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    write_secret(&path, &seed)?;

    println!("Newsroom signing key generated.\n");
    println!("Saved to:               {}", path.display());
    println!("Newsroom verifying key: {}\n", hex::encode(vk));
    println!("Hand this verifying key to FPF for signing.");
    Ok(())
}

pub fn show_vk() -> Result<()> {
    let kp = load_keypair()?;
    println!("{}", hex::encode(kp.verifying_key().into_bytes()));
    Ok(())
}

pub fn set_fpf_sig(sig_hex: &str, fpf_vk_hex: &str, force: bool) -> Result<()> {
    let mut sig_bytes = [0u8; 64];
    hex::decode_to_slice(sig_hex.trim(), &mut sig_bytes).context("parsing FPF signature")?;
    let mut fpf_vk_bytes = [0u8; 32];
    hex::decode_to_slice(fpf_vk_hex.trim(), &mut fpf_vk_bytes)
        .context("parsing FPF verifying key")?;

    let path = fpf_sig_path()?;
    if path.exists() && !force {
        bail!(
            "an FPF signature already exists at {}\nuse `newsroom set-fpf-sig --force` to overwrite it",
            path.display()
        );
    }

    let nr_kp = load_keypair()?;
    let vk_nr_bytes = nr_kp.verifying_key().into_bytes();
    let vk_fpf = VerifyingKey::from_bytes(fpf_vk_bytes);
    let sig = Signature::<FpfOnNewsroom>::from_bytes(sig_bytes);

    vk_fpf
        .verify(&vk_nr_bytes, &sig)
        .context("FPF signature does not verify against this newsroom's verifying key")?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    write_secret(&path, &sig_bytes)?;

    println!("FPF signature verified and stored.\n");
    println!("Saved to: {}", path.display());
    Ok(())
}

pub fn start(port: u16) -> Result<()> {
    let rt = tokio::runtime::Runtime::new().context("starting tokio runtime")?;
    rt.block_on(serve(port))
}

async fn serve(port: u16) -> Result<()> {
    let kp = load_keypair()?;
    let state = AppState {
        vk_hex: Arc::new(hex::encode(kp.verifying_key().into_bytes())),
        newsroom_kp: Arc::new(kp),
        journalists: Arc::new(Mutex::new(HashMap::new())),
        ephemeral_keys: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/", get(|| async { "securedrop newsroom (demo)\n" }))
        .route("/newsroom", get(get_newsroom))
        .route("/newsroom/journalists/enroll", post(post_enroll))
        .route("/newsroom/journalists/keys", post(post_replenish))
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

async fn get_newsroom(State(state): State<AppState>) -> Json<NewsroomInfo> {
    Json(NewsroomInfo {
        verifying_key: (*state.vk_hex).clone(),
    })
}

async fn post_enroll(
    State(state): State<AppState>,
    Json(req): Json<JournalistSetupRequest>,
) -> Result<Json<JournalistSetupResponse>, (StatusCode, String)> {
    let vk_j = req.enrollment.keys.0;
    vk_j.verify(req.enrollment.bundle.as_bytes(), &req.enrollment.selfsig)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "journalist self-signature does not verify".to_string(),
            )
        })?;

    let sig = state.newsroom_kp.sign(&vk_j.into_bytes());

    // Record the enrollment so this journalist can later replenish ephemeral keys.
    let vk_hex = hex::encode(vk_j.into_bytes());
    state
        .journalists
        .lock()
        .expect("can get journalist mutex")
        .insert(vk_hex, req.enrollment);

    Ok(Json(JournalistSetupResponse { sig }))
}

/// Ephemeral key replenishment
async fn post_replenish(
    State(state): State<AppState>,
    Json(req): Json<JournalistEphemeralKeyRequest>,
) -> Result<Json<JournalistEphemeralKeyResponse>, (StatusCode, String)> {
    let vk_j = req.verifying_key;
    let vk_hex = hex::encode(vk_j.into_bytes());

    // Only enrolled journalists may upload ephemeral keys.
    if !state
        .journalists
        .lock()
        .expect("journalists mutex poisoned")
        .contains_key(&vk_hex)
    {
        return Err((
            StatusCode::FORBIDDEN,
            "journalist is not enrolled with this newsroom".to_string(),
        ));
    }

    // Verify each bundle's self-signature against the journalist's verifying key.
    for (bundle, selfsig) in &req.bundles {
        vk_j.verify(&bundle.as_bytes(), selfsig).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "ephemeral key bundle self-signature does not verify".to_string(),
            )
        })?;
    }

    let mut store = state
        .ephemeral_keys
        .lock()
        .expect("ephemeral_keys mutex poisoned");
    let stored = store.entry(vk_hex).or_default();
    stored.extend(req.bundles);

    Ok(Json(JournalistEphemeralKeyResponse {
        stored: stored.len(),
    }))
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("install ctrl-c handler");
    println!("\nShutting down.");
}

fn load_keypair() -> Result<NewsroomKeyPair> {
    let path = key_path()?;
    let bytes = fs::read(&path)
        .with_context(|| format!("reading {} (run `newsroom init` first)", path.display()))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!("{} is {} bytes, expected 32", path.display(), v.len())
    })?;
    Ok(NewsroomKeyPair::from_bytes(seed))
}

fn key_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom").join("newsroom.key"))
}

fn fpf_sig_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom").join("fpf-sig.bin"))
}
