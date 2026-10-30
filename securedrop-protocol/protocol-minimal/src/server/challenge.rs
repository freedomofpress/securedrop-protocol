use crate::challenge::{derive_challenge_key, encrypt_message_id};
use crate::keys::NR_ID;
use crate::primitives::provider::constants::{LEN_KMID, LEN_MESSAGE_ID};
use crate::primitives::ristretto255::{
    dh_shared_secret, generate_random_scalar, random_dh_public_key,
};
use crate::{DHPublicKey, Envelope, FetchResponse};
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

/// Given a set of ciphertext bundles (C, X, Z) and their associated uuid,
/// compute a fixed-length set of "challenges" >= the number of SeverMessageStore entries.
/// A challenge is returned as a tuple of DH agreement outputs (or random data tuples of the same length).
/// For benchmarking purposes, supply the rng as a separable parameter, and allow the total number of expected responses to be specified as a paremeter (worst case performance
/// when the number of items in the server store approaches num total_responses.)
///
/// Note this is marked lax temporaily due to the `push` panic freedom requirement
#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
pub fn compute_fetch_challenges<R: RngCore + CryptoRng>(
    rng: &mut R,
    entries: &[([u8; LEN_MESSAGE_ID], Envelope)],
    total_responses: usize,
) -> Vec<FetchResponse> {
    let mut responses = Vec::with_capacity(total_responses);

    // Generate two random DH public keys to use to generate the padded responses. Sampling two independently at random mimics the distribution of those sent by the client.
    let decoy_mgdh = random_dh_public_key(rng);
    let decoy_mgdh_pubkey = random_dh_public_key(rng);

    for (message_id, envelope) in entries.iter() {
        if responses.len() < total_responses {
            responses.push(make_response(
                rng,
                message_id,
                &envelope.mgdh,
                &envelope.mgdh_pubkey,
                NR_ID,
            ));
        }
    }

    // Pad if needed to return fixed length of responses
    while responses.len() < total_responses {
        responses.push(make_response(
            rng,
            &[0u8; LEN_MESSAGE_ID],
            &decoy_mgdh,
            &decoy_mgdh_pubkey,
            NR_ID,
        ));
    }
    responses
}

/// Note this is marked lax temporaily due to the `.expect()` panic freedom requirement
#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
fn make_response<R: RngCore + CryptoRng>(
    rng: &mut R,
    message_id: &[u8; LEN_MESSAGE_ID],
    mgdh: &DHPublicKey,
    mgdh_pubkey: &DHPublicKey,
    nr_id: &[u8],
) -> FetchResponse {
    // Generate ephemeral scalar r, fresh per message
    let eph_sk = generate_random_scalar(&mut *rng);

    // 3-party DH yields shared_secret used to encrypt message_id
    let shared_secret = dh_shared_secret(mgdh, &eph_sk);
    let key = derive_challenge_key(&shared_secret, nr_id).unwrap();
    let enc_mid = encrypt_message_id(&key, message_id).unwrap();

    // `copy_from_slice` rather than `try_into()`: Core_models has no
    // `TryInto<Vec<u8>, [u8; N]>` instance, and this is the codebase's
    // Vec->array idiom. (Lengths must match; covered by `lax`.)
    let mut kmid = [0u8; LEN_KMID];
    kmid.copy_from_slice(&enc_mid);

    // 2-party DH yields per-request clue (pmgdh) used by intended recipient
    // to compute shared_secret
    let pmgdh = dh_shared_secret(mgdh_pubkey, &eph_sk);

    FetchResponse {
        enc_id: kmid,
        pmgdh,
    }
}
