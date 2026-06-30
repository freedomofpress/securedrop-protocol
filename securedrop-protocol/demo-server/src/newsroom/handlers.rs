use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use rand::{Rng, RngExt};
use securedrop_protocol_minimal::encrypt_decrypt::compute_fetch_challenges;
use securedrop_protocol_minimal::primitives::MESSAGE_ID_FETCH_SIZE;
use securedrop_protocol_minimal::wire::core::{
    MessageChallengeFetchResponse, SourceJournalistKeyResponse, SourceNewsroomKeyResponse,
};
use securedrop_protocol_minimal::wire::setup::{
    JournalistEphemeralKeyRequest, JournalistEphemeralKeyResponse, JournalistSetupRequest,
    JournalistSetupResponse,
};
use securedrop_protocol_minimal::{Envelope, JournalistPublicView};
use serde::Serialize;
use uuid::Uuid;

use super::server::{AppState, EnrolledJournalist};

#[derive(Serialize)]
pub(crate) struct NewsroomInfo {
    verifying_key: String,
}

#[derive(Serialize)]
pub(crate) struct MessageSubmitResponse {
    message_id: String,
}

pub(crate) async fn get_newsroom(State(state): State<AppState>) -> Json<NewsroomInfo> {
    Json(NewsroomInfo {
        verifying_key: (*state.vk_hex).clone(),
    })
}

pub(crate) async fn post_enroll(
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
pub(crate) async fn post_replenish(
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
pub(crate) async fn get_newsroom_keys(
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
pub(crate) async fn get_journalist_keys(
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

    let mut rng = rand::rng();
    let mut responses = Vec::new();
    for (vk_hex, enrolled) in journalists.iter() {
        let Some(bundles) = ephemeral_keys.get_mut(vk_hex).filter(|b| !b.is_empty()) else {
            continue;
        };
        let idx = rng.random_range(0..bundles.len());
        let bundle = bundles.swap_remove(idx);

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
pub(crate) async fn post_message(
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
pub(crate) async fn get_challenges(
    State(state): State<AppState>,
) -> Json<MessageChallengeFetchResponse> {
    let mut rng = rand::rng();
    let store = state.messages.lock().expect("messages mutex poisoned");
    let entries: Vec<_> = store
        .iter()
        .take(MESSAGE_ID_FETCH_SIZE)
        .map(|(uuid, envelope)| (*uuid.as_bytes(), envelope.clone()))
        .collect();
    let messages = compute_fetch_challenges(&mut rng, &entries, MESSAGE_ID_FETCH_SIZE);

    Json(MessageChallengeFetchResponse {
        count: messages.len(),
        messages,
    })
}

/// Message download: the server returns the stored envelope for a
/// message ID that a recipient recovered from the challenges.
pub(crate) async fn get_message(
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

/// A recipient deletes a message once it has been received.
pub(crate) async fn delete_message(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let message_id = Uuid::parse_str(id.trim())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid message ID".to_string()))?;

    let removed = state
        .messages
        .lock()
        .expect("messages mutex poisoned")
        .remove(&message_id)
        .is_some();

    if removed {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((StatusCode::NOT_FOUND, "no such message".to_string()))
    }
}
