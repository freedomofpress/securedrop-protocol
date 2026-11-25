use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use securedrop_protocol_minimal::Envelope;
use securedrop_protocol_minimal::wire::core::{
    JournalistEphemeralKeys, MessageChallengeFetchRequest, MessageChallengeFetchResponse,
    MessageFetchRequest, WelcomeBundle,
};
use securedrop_protocol_minimal::wire::setup::{
    JournalistEphemeralKeyRequest, JournalistEphemeralKeyResponse, JournalistSetupRequest,
    JournalistSetupResponse,
};
use serde::Serialize;
use uuid::Uuid;

use super::server::AppState;

#[derive(Serialize)]
pub(crate) struct MessageSubmitResponse {
    message_id: String,
}

/// Journalist enrollment.
///
/// DEMO ONLY! This endpoint is unauthenticated.
///
/// In production, enrollment is an offline, admin-authorized operation.
pub(crate) async fn post_enroll(
    State(state): State<AppState>,
    Json(req): Json<JournalistSetupRequest>,
) -> Result<Json<JournalistSetupResponse>, (StatusCode, String)> {
    // Records the enrollment (with the newsroom signature) so this journalist can
    // later replenish ephemeral keys and be served to sources.
    state
        .lock()
        .expect("server mutex poisoned")
        .setup_journalist(req)
        .map(Json)
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "journalist self-signature does not verify".to_string(),
            )
        })
}

/// Ephemeral key replenishment
pub(crate) async fn post_replenish(
    State(state): State<AppState>,
    Json(req): Json<JournalistEphemeralKeyRequest>,
) -> Result<Json<JournalistEphemeralKeyResponse>, (StatusCode, String)> {
    let mut server = state.lock().expect("server mutex poisoned");

    // Only enrolled journalists may upload ephemeral keys.
    if !server.is_enrolled(&req.verifying_key) {
        return Err((
            StatusCode::FORBIDDEN,
            "journalist is not enrolled with this newsroom".to_string(),
        ));
    }

    // Verifies each bundle's self-signature against the journalist's verifying key.
    let stored = server.handle_ephemeral_key_request(req).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "ephemeral key bundle self-signature does not verify".to_string(),
        )
    })?;

    Ok(Json(JournalistEphemeralKeyResponse { stored }))
}

pub(crate) async fn get_welcome(
    State(state): State<AppState>,
) -> Result<Json<WelcomeBundle>, (StatusCode, String)> {
    state
        .lock()
        .expect("server mutex poisoned")
        .handle_welcome()
        .map(Json)
        .map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "newsroom has no FPF signature stored (run `newsroom set-fpf-sig`)".to_string(),
            )
        })
}

pub(crate) async fn get_journalist_ephemeral_keys(
    State(state): State<AppState>,
) -> Json<Vec<JournalistEphemeralKeys>> {
    Json(
        state
            .lock()
            .expect("server mutex poisoned")
            .handle_journalist_ephemeral_keys(&mut rand::rng()),
    )
}

/// Stores the source's envelope under a freshly generated message ID and returns the ID.
pub(crate) async fn post_message(
    State(state): State<AppState>,
    Json(envelope): Json<Envelope>,
) -> Json<MessageSubmitResponse> {
    let message_id = state
        .lock()
        .expect("server mutex poisoned")
        .handle_message_submit(envelope, &mut rand::rng());

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
    Json(
        state
            .lock()
            .expect("server mutex poisoned")
            .handle_request_challenges(MessageChallengeFetchRequest {}, &mut rand::rng()),
    )
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
        .lock()
        .expect("server mutex poisoned")
        .handle_message_fetch(MessageFetchRequest { message_id })
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, "no such message".to_string()))
}
