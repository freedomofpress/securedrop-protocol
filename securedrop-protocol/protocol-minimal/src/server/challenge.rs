use crate::challenge::{derive_challenge_key, encrypt_message_id};
use crate::keys::NR_ID;
use crate::primitives::provider::constants::{LEN_KMID, LEN_MESSAGE_ID};
use crate::primitives::ristretto255::{
    dh_shared_secret, generate_random_scalar, random_dh_public_key,
};
use crate::{Envelope, FetchResponse};
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

// Sort by encrypted id
// Marked as opaque to bypass typeclass constraint error due to missing Ord implementation
#[cfg_attr(hax, hax_lib::opaque)]
fn sort_by_id(entries: &mut [FetchResponse]) {
    entries.sort_by_key(|a| a.enc_id)
}

/// Given a set of ciphertext bundles (C, X, Z) and their associated uuid,
/// compute a fixed-length set of "challenges" >= the number of SeverMessageStore entries.
/// A challenge is returned as a tuple of DH agreement outputs (or random data tuples of the same length).
/// For benchmarking purposes, supply the rng as a separable parameter, and allow the total number of expected responses to be specified as a paremeter (worst case performance
/// when the number of items in the server store approaches num total_responses.)
///
/// Note this is marked lax temporaily due to the `.expect()`/`push` panic freedom requirement
#[cfg_attr(hax, hax_lib::fstar::verification_status(lax))]
pub fn compute_fetch_challenges<R: RngCore + CryptoRng>(
    rng: &mut R,
    entries: &[([u8; LEN_MESSAGE_ID], Envelope)],
    total_responses: usize,
) -> Vec<FetchResponse> {
    let mut responses = Vec::with_capacity(total_responses);

    for (message_id, envelope) in entries.iter() {
        // TODO(#423): Handle what should happen if there are more entries than total_responses
        if responses.len() < total_responses {
            // Generate ephemeral scalar r, fresh per message
            let eph_sk = generate_random_scalar(&mut *rng);

            // 3-party DH yields shared_secret used to encrypt message_id
            let shared_secret = dh_shared_secret(&envelope.mgdh, &eph_sk);
            let key = derive_challenge_key(&shared_secret, NR_ID).unwrap();
            let enc_mid = encrypt_message_id(&key, message_id).unwrap();

            // `copy_from_slice` rather than `try_into()`: Core_models has no
            // `TryInto<Vec<u8>, [u8; N]>` instance, and this is the codebase's
            // Vec->array idiom. (Lengths must match; covered by `lax`.)
            let mut kmid = [0u8; LEN_KMID];
            kmid.copy_from_slice(&enc_mid);

            // 2-party DH yields per-request clue (pmgdh) used by intended recipient
            // to compute shared_secret
            let pmgdh = dh_shared_secret(&envelope.mgdh_pubkey, &eph_sk);

            responses.push(FetchResponse {
                enc_id: kmid,
                pmgdh,
            });
        }
    }

    // Pad if needed to return fixed length of responses
    while responses.len() < total_responses {
        let mut pad_kmid: [u8; LEN_KMID] = [0u8; LEN_KMID];
        rng.fill_bytes(&mut pad_kmid);

        responses.push(FetchResponse {
            enc_id: pad_kmid,
            pmgdh: random_dh_public_key(rng),
        });
    }

    // Sort responses lexicographically by enc_id to hide real vs decoy challenges
    sort_by_id(&mut responses);
    responses
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use crate::message::MessageCiphertext;
    use crate::metadata::{LEN_METADATA_CIPHERTEXT, MetadataCiphertext};
    use crate::primitives::dh_akem::DH_AKEM_ENCAPS_SECRET_LEN;
    use crate::primitives::mlkem::LEN_MLKEM_SHAREDSECRET_ENCAPS;
    use crate::primitives::xwing::LEN_XWING_SHAREDSECRET_ENCAPS;

    use super::*;

    // Test purposes only!
    fn setup_rng() -> impl rand_core::CryptoRng + rand_core::RngCore {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("getrandom failed- is platform supported?");
        ChaCha20Rng::from_seed(seed)
    }

    /// Trivial envelope for testing
    fn envelope<R: RngCore + CryptoRng>(rng: &mut R) -> Envelope {
        Envelope {
            ct_apke: MessageCiphertext {
                c1: [0u8; DH_AKEM_ENCAPS_SECRET_LEN],
                cp: [0u8; 128].to_vec(),
                c2: [0u8; LEN_MLKEM_SHAREDSECRET_ENCAPS],
            },
            ct_pke: MetadataCiphertext {
                c: [0u8; LEN_XWING_SHAREDSECRET_ENCAPS],
                cp: [0u8; LEN_METADATA_CIPHERTEXT],
            },
            mgdh_pubkey: random_dh_public_key(rng),
            mgdh: random_dh_public_key(rng),
        }
    }

    #[test]
    fn test_fixed_response_length() {
        let mut rng = setup_rng();
        let total_challenges: usize = 10;
        let total_responses: usize = 15;

        // Use trivial envelopes, sorting is done in encrypted IDs
        let env = envelope(&mut rng);

        let mut entries = Vec::with_capacity(total_challenges);
        for _ in 0..total_challenges {
            let mut message_id: [u8; LEN_MESSAGE_ID] = [0u8; LEN_MESSAGE_ID];
            rng.fill_bytes(&mut message_id);
            entries.push((message_id, env.clone()));
        }

        let responses = compute_fetch_challenges(&mut rng, &entries, total_responses);
        assert_eq!(responses.len(), total_responses);
    }

    #[test]
    fn test_fixed_response_length_more_challenges() {
        let mut rng = setup_rng();
        let total_challenges: usize = 20;
        let total_responses: usize = 15;

        // Use trivial envelopes, sorting is done in encrypted IDs
        let env = envelope(&mut rng);

        let mut entries = Vec::with_capacity(total_challenges);
        for _ in 0..total_challenges {
            let mut message_id: [u8; LEN_MESSAGE_ID] = [0u8; LEN_MESSAGE_ID];
            rng.fill_bytes(&mut message_id);
            entries.push((message_id, env.clone()));
        }

        let responses = compute_fetch_challenges(&mut rng, &entries, total_responses);
        assert_eq!(responses.len(), total_responses);
    }

    #[test]
    fn test_sorted_responses() {
        let mut rng = setup_rng();
        let total_challenges: usize = 10;
        let total_responses: usize = 15;

        // Use trivial envelopes, sorting is done in encrypted IDs
        let env = envelope(&mut rng);

        let mut entries = Vec::with_capacity(total_challenges);
        for _ in 0..total_challenges {
            let mut message_id: [u8; LEN_MESSAGE_ID] = [0u8; LEN_MESSAGE_ID];
            rng.fill_bytes(&mut message_id);
            entries.push((message_id, env.clone()));
        }

        let responses = compute_fetch_challenges(&mut rng, &entries, total_responses);
        assert!(
            responses
                .iter()
                .is_sorted_by_key(|response| response.enc_id)
        );
    }
}
