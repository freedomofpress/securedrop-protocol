use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use axum::http::StatusCode;
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use rand_core::{OsRng, TryRngCore};
use securedrop_protocol_minimal::encrypt_decrypt::compute_fetch_challenges;
use securedrop_protocol_minimal::keys::NewsroomKeyPair;
use securedrop_protocol_minimal::primitives::MESSAGE_ID_FETCH_SIZE;
use securedrop_protocol_minimal::storage::ServerMessageStore;
use securedrop_protocol_minimal::wire::core::{
    MessageChallengeFetchResponse, SourceJournalistKeyResponse, SourceNewsroomKeyResponse,
};
use securedrop_protocol_minimal::wire::setup::{
    JournalistEphemeralKeyRequest, JournalistEphemeralKeyResponse, JournalistSetupRequest,
    JournalistSetupResponse,
};
use securedrop_protocol_minimal::{
    Enrollment, Envelope, FpfOnNewsroom, JournalistPublicView, NewsroomOnJournalist, Signature,
    SignedKeyBundlePublic, VerifyingKey,
};
use serde::Serialize;
use uuid::Uuid;

use crate::state::{data_dir, write_secret};

/// An enrolled journalist's long term enrollment together with the newsroom's
/// signature over their verifying key - together so it can be served to sources.
#[derive(Clone)]
struct EnrolledJournalist {
    enrollment: Enrollment,
    nr_sig: Signature<NewsroomOnJournalist>,
}

/// In-memory newsroom state
///
/// Note: demo only, in memory only, nothing yet persisted to disk
#[derive(Clone)]
struct AppState {
    vk_hex: Arc<String>,
    newsroom_kp: Arc<NewsroomKeyPair>,
    /// FPF's signature over the newsroom verifying key
    fpf_sig: Option<Signature<FpfOnNewsroom>>,
    /// Enrolled journalists, keyed by long term verifying key
    journalists: Arc<Mutex<HashMap<String, EnrolledJournalist>>>,
    /// Stored ephemeral key bundles, keyed by journalist verifying key
    ephemeral_keys: Arc<Mutex<HashMap<String, Vec<SignedKeyBundlePublic>>>>,
    /// Submitted messages, keyed by server-assigned message ID
    messages: Arc<Mutex<ServerMessageStore>>,
}

#[derive(Serialize)]
struct NewsroomInfo {
    verifying_key: String,
}

#[derive(Serialize)]
struct MessageSubmitResponse {
    message_id: String,
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
        .route("/messages/:id", get(get_message))
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

    // Record the enrollment (with the newsroom signature) so this journalist can
    // later replenish ephemeral keys and be served to sources.
    let vk_hex = hex::encode(vk_j.into_bytes());
    state
        .journalists
        .lock()
        .expect("can get journalist mutex")
        .insert(
            vk_hex,
            EnrolledJournalist {
                enrollment: req.enrollment,
                nr_sig: sig,
            },
        );

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
        .expect("can get journalists mutex")
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

/// Retrieves the newsroom verifying key together with FPF's signature over it
async fn get_newsroom_keys(
    State(state): State<AppState>,
) -> Result<Json<SourceNewsroomKeyResponse>, (StatusCode, String)> {
    let fpf_sig = state.fpf_sig.ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "newsroom has no FPF signature stored (run `newsroom set-fpf-sig`)".to_string(),
    ))?;

    Ok(Json(SourceNewsroomKeyResponse {
        newsroom_verifying_key: state.newsroom_kp.verifying_key(),
        fpf_sig,
    }))
}

/// For each enrolled journalist with ephemeral keys available, the server consumes one one-time bundle
/// and returns the journalist's long term public view plus the newsroom's signature.
async fn get_journalist_keys(
    State(state): State<AppState>,
) -> Json<Vec<SourceJournalistKeyResponse>> {
    let journalists = state
        .journalists
        .lock()
        .expect("journalists mutex poisoned");
    let mut ephemeral_keys = state
        .ephemeral_keys
        .lock()
        .expect("ephemeral_keys mutex poisoned");

    let mut responses = Vec::new();
    for (vk_hex, enrolled) in journalists.iter() {
        // Consume one one-time ephemeral bundle and skip any journos with no bundles left.
        let Some(bundle) = ephemeral_keys.get_mut(vk_hex).and_then(Vec::pop) else {
            continue;
        };

        let e = &enrolled.enrollment;
        let journalist = JournalistPublicView::new(
            e.keys.0,
            e.keys.1.clone(),
            e.keys.2.clone(),
            e.selfsig,
            e.bundle.clone(),
            bundle,
        );

        responses.push(SourceJournalistKeyResponse {
            journalist,
            nr_signature: enrolled.nr_sig,
        });
    }

    Json(responses)
}

/// Stores the source's envelope under a freshly generated message ID and returns the ID.
async fn post_message(
    State(state): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Json<MessageSubmitResponse> {
    let message_id = Uuid::new_v4();
    state
        .messages
        .lock()
        .expect("can get messages mutex")
        .insert(message_id, envelope);

    Json(MessageSubmitResponse {
        message_id: message_id.to_string(),
    })
}

/// Message ID fetch: the server returns a fixed size set of per-request
/// challenges (encrypted message IDs + DH clues) computed over all stored
/// messages, which only the intended recipient can solve with their fetch key.
async fn get_challenges(State(state): State<AppState>) -> Json<MessageChallengeFetchResponse> {
    let mut rng = OsRng.unwrap_err();
    let store = state.messages.lock().expect("messages mutex poisoned");
    let messages = compute_fetch_challenges(&mut rng, &store, MESSAGE_ID_FETCH_SIZE);

    Json(MessageChallengeFetchResponse {
        count: messages.len(),
        messages,
    })
}

/// Message download: the server returns the stored envelope for a
/// message ID that a recipient recovered from the challenges.
async fn get_message(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Envelope>, (StatusCode, String)> {
    let message_id = Uuid::parse_str(id.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid message ID".to_string()))?;

    state
        .messages
        .lock()
        .expect("messages mutex poisoned")
        .get(&message_id)
        .cloned()
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "no such message".to_string()))
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

/// Load the stored FPF signature over the newsroom verifying key if present
fn load_fpf_sig() -> Result<Option<Signature<FpfOnNewsroom>>> {
    let path = fpf_sig_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let sig_bytes: [u8; 64] = bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!("{} is {} bytes, expected 64", path.display(), v.len())
    })?;
    Ok(Some(Signature::<FpfOnNewsroom>::from_bytes(sig_bytes)))
}

fn key_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom").join("newsroom.key"))
}

fn fpf_sig_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("newsroom").join("fpf-sig.bin"))
}
