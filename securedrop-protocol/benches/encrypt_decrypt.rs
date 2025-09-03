use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

use hpke_rs::{HpkeKeyPair, HpkePrivateKey, HpkePublicKey};
use libcrux_curve25519::hacl::scalarmult;
use rand::RngCore;
use rand::rngs::StdRng;
use rand_core::CryptoRng;
use rand_core::SeedableRng;
use securedrop_protocol::primitives::dh_akem::generate_dh_akem_keypair;
use securedrop_protocol::primitives::mlkem::generate_mlkem768_keypair;
use securedrop_protocol::primitives::x25519::generate_random_scalar;
use securedrop_protocol::primitives::xwing::generate_xwing_keypair;
use std::vec::Vec;

const HPKE_PSK_ID: &[u8] = b"PSK_INFO_ID_TAG"; // Spec requires a tag
const HPKE_INFO: &[u8] = b"";
const HPKE_AAD: &[u8] = b"";

// Key lengths
const LEN_DHKEM_ENCAPS_KEY: usize = libcrux_curve25519::EK_LEN;
const LEN_DHKEM_DECAPS_KEY: usize = libcrux_curve25519::DK_LEN;
const LEN_DHKEM_SHAREDSECRET_ENCAPS: usize = libcrux_curve25519::SS_LEN;
const LEN_DHKEM_SHARED_SECRET: usize = libcrux_curve25519::SS_LEN;
const LEN_DH_ITEM: usize = LEN_DHKEM_DECAPS_KEY;

// https://openquantumsafe.org/liboqs/algorithms/kem/ml-kem.html
// todo, source from crates instead of hardcoding
const LEN_MLKEM_ENCAPS_KEY: usize = 1184;
const LEN_MLKEM_DECAPS_KEY: usize = 2400;
const LEN_MLKEM_SHAREDSECRET_ENCAPS: usize = 1088;
const LEN_MLKEM_SHAREDSECRET: usize = 32;
const LEN_MLKEM_RAND_SEED_SIZE: usize = 64;

// https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-01.html#name-encoding-and-sizes
const LEN_XWING_ENCAPS_KEY: usize = 1216;
const LEN_XWING_DECAPS_KEY: usize = 2464;
const LEN_XWING_SHAREDSECRET_ENCAPS: usize = 1120;
const LEN_XWING_SHAREDSECRET: usize = 32;
const LEN_XWING_RAND_SEED_SIZE: usize = 96;

#[derive(Debug)]
pub struct Envelope {
    cmessage: Vec<u8>,
    cmetadata: Vec<u8>,
    metadata_encap: Vec<u8>,
    mgdh_pubkey: Vec<u8>,
    mgdh: Vec<u8>,
}

#[derive(Debug)]
pub struct Plaintext {
    msg: Vec<u8>,
    sender_key: Vec<u8>,
    recipient_reply_key_classical_msg: Option<Vec<u8>>, // DH-AKEM
    recipient_reply_key_pq_psk_msg: Option<Vec<u8>>,    // ML-KEM768
    recipient_reply_key_hybrid_md: Option<Vec<u8>>,     // XWING
}

pub struct Metadata {}

pub trait User {
    // msg enc classical
    fn get_dhakem_sk(&self) -> &[u8];
    fn get_dhakem_pk(&self) -> &[u8];

    // msg enc pq psk
    fn get_pq_kem_psk_pk(&self) -> &[u8];
    fn get_pq_kem_psk_sk(&self) -> &[u8];

    // md enc hybrid
    fn get_hybrid_md_pk(&self) -> &[u8];
    fn get_hybrid_md_sk(&self) -> &[u8];

    // fetch classical
    fn get_fetch_sk(&self) -> &[u8];
    fn get_fetch_pk(&self) -> &[u8];
}

pub fn hpke_keypair_from_bytes(sk_bytes: &[u8], pk_bytes: &[u8]) -> HpkeKeyPair {
    HpkeKeyPair::from((sk_bytes, pk_bytes))
}

pub fn hpke_pubkey_from_bytes(pk_bytes: &[u8]) -> HpkePublicKey {
    HpkePublicKey::from(pk_bytes)
}

pub fn encrypt<R: RngCore + CryptoRng>(
    rng: &mut R,
    sender: &dyn User,
    plaintext: &[u8],
    recipient: &dyn User,
) -> Envelope {
    use hpke_rs::hpke_types::AeadAlgorithm::ChaCha20Poly1305;
    use hpke_rs::hpke_types::KdfAlgorithm::HkdfSha256;
    use hpke_rs::hpke_types::KemAlgorithm::{DhKem25519, XWingDraft06};
    use hpke_rs::{Hpke, Mode};

    let hpke_authenc = Hpke::new(Mode::AuthPsk, DhKem25519, HkdfSha256, ChaCha20Poly1305);

    let recipient_hpke_pubkey_msg = hpke_pubkey_from_bytes(recipient.get_dhakem_pk());

    let sender_hpke_keypair =
        hpke_keypair_from_bytes(sender.get_dhakem_sk(), sender.get_dhakem_pk());

    // HPKE AuthPSK message enc - TODO type
    let (enc, ct) = hpke_authenc.seal(
        &recipient_hpke_pubkey_msg,
        b"", // info
        b"", // aad
        plaintext,
        Some(b"PQ_KEM_SS"),                      // PSK TODO PQ KEM
        Some(b"PSK_INFO_ID_TAG"),                // Fixed PSK ID
        Some(sender_hpke_keypair.private_key()), // sender private key
    );

    // mgdh
    let eph_sk: [u8; LEN_DH_ITEM] =
        generate_random_scalar(rng).expect("DH keygen (ephemeral fetch) failed!");
    let mut eph_pk: [u8; LEN_DH_ITEM] = [0u8; LEN_DH_ITEM];
    libcrux_curve25519::secret_to_public(&eph_pk, &eph_sk); // todo
    let mut out_scalarmult = [0u8; LEN_DH_ITEM];
    let shared_mgdh = scalarmult(
        &mut out_scalarmult,
        &eph_sk.to_bytes(),
        recipient.get_fetch_pk(),
    );

    Envelope {
        cmessage: ct,
        cmetadata: vec![], // TODO
        metadata_encap: enc,
        mgdh_pubkey: eph_pk.as_bytes().to_vec(),
        mgdh: shared_mgdh,
    }
}

pub fn decrypt(receiver: &dyn User, envelope: &Envelope) -> Plaintext {
    use hpke_rs::hpke_types::AeadAlgorithm::ChaCha20Poly1305;
    use hpke_rs::hpke_types::KdfAlgorithm::HkdfSha256;
    use hpke_rs::hpke_types::KemAlgorithm::{DhKem25519, XWingDraft06};
    use hpke_rs::{Hpke, Mode};

    let hpke_authenc = Hpke::new(Mode::AuthPsk, DhKem25519, HkdfSha256, ChaCha20Poly1305);

    let hpke_keypair_receiver =
        hpke_keypair_from_bytes(receiver.get_dhakem_sk(), receiver.get_dhakem_pk());

    // TODO from metadata
    let hpke_pubkey_sender = hpke_pubkey_from_bytes();

    let pt = hpke_authenc
        .open(
            &envelope.metadata_encap,
            hpke_keypair_receiver.private_key(),
            b"",
            b"",
            &envelope.cmessage,
            Some(b"sharedsecret"),
            Some(b"PSK_INFO_ID_TAG"),
            Some(&envelope.mgdh_pubkey), // no, not this key! TODO key parsed from metadata
        )
        .expect("Decryption failed");

    // TODO
    Plaintext {
        msg: pt,
        sender_key: envelope.mgdh_pubkey.clone(), // no, not this key!
        recipient_reply_key_classical_msg: None,
        recipient_reply_key_pq_psk_msg: None,
        recipient_reply_key_hybrid_md: None,
    }
}

pub struct Source {
    sk_dh: [u8; LEN_DHKEM_DECAPS_KEY],
    pk_dh: [u8; LEN_DHKEM_ENCAPS_KEY],
    sk_pqkem_psk: [u8; LEN_MLKEM_DECAPS_KEY],
    pk_pqkem_psk: [u8; LEN_MLKEM_ENCAPS_KEY],
    sk_md: [u8; LEN_XWING_DECAPS_KEY],
    pk_md: [u8; LEN_XWING_ENCAPS_KEY],
    sk_fetch: [u8; LEN_DH_ITEM],
    pk_fetch: [u8; LEN_DH_ITEM],
}

impl Source {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk_dh: [u8; LEN_DHKEM_DECAPS_KEY] =
            generate_random_scalar(rng).expect("DH keygen (ephemeral fetch) failed!");
        let mut pubkey: [u8; LEN_DH_ITEM] = [0u8; LEN_DH_ITEM];
        let pk_dh = libcrux_curve25519::secret_to_public(&sk_dh, &mut pubkey);
        let sk_fetch: [u8; LEN_DHKEM_DECAPS_KEY] =
            generate_random_scalar(rng).expect("DH keygen (ephemeral fetch) failed!");
        let pk_fetch = libcrux_curve25519::secret_to_public(&sk_dh, &mut pubkey);
        Self {
            sk_dh,
            pk_dh,
            sk_pqkem_psk: sk_msg,
            pk_pqkem_psk: pk_msg,
            sk_md,
            pk_md,
            sk_fetch,
            pk_fetch,
        }
    }
}

impl User for Source {
    fn get_dhakem_sk(&self) -> &[u8] {
        &self.sk_dh
    }
    fn get_dhakem_pk(&self) -> &[u8] {
        &self.pk_dh
    }
    fn get_fetch_sk(&self) -> &[u8] {
        &self.sk_fetch
    }
    fn get_fetch_pk(&self) -> &[u8] {
        &self.pk_fetch
    }
    fn get_hybrid_md_pk(&self) -> &[u8] {
        &self.pk_md
    }
    fn get_hybrid_md_sk(&self) -> &[u8] {
        &self.sk_md
    }
    fn get_pq_kem_psk_pk(&self) -> &[u8] {
        &self.sk_pqkem_psk
    }
    fn get_pq_kem_psk_sk(&self) -> &[u8] {
        &self.sk_pqkem_psk
    }
}

pub struct Journalist {
    sk_dh: [u8; LEN_DHKEM_DECAPS_KEY],
    pk_dh: [u8; LEN_DHKEM_ENCAPS_KEY],
    sk_pqkem_psk: [u8; LEN_MLKEM_DECAPS_KEY],
    pk_pqkem_psk: [u8; LEN_MLKEM_ENCAPS_KEY],
    sk_md: [u8; LEN_XWING_DECAPS_KEY],
    pk_md: [u8; LEN_XWING_ENCAPS_KEY],
    sk_fetch: [u8; LEN_DH_ITEM],
    pk_fetch: [u8; LEN_DH_ITEM],
}

impl Journalist {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        unimplemented!() // TODO!
    }
}

impl User for Journalist {
    fn get_dhakem_sk(&self) -> &[u8] {
        &self.sk_dh
    }
    fn get_dhakem_pk(&self) -> &[u8] {
        &self.pk_dh
    }
    fn get_fetch_sk(&self) -> &[u8] {
        &self.sk_fetch
    }
    fn get_fetch_pk(&self) -> &[u8] {
        &self.pk_fetch
    }
    fn get_hybrid_md_pk(&self) -> &[u8] {
        &self.pk_md
    }
    fn get_hybrid_md_sk(&self) -> &[u8] {
        &self.sk_md
    }
    fn get_pq_kem_psk_pk(&self) -> &[u8] {
        &self.sk_pqkem_psk
    }
    fn get_pq_kem_psk_sk(&self) -> &[u8] {
        &self.sk_pqkem_psk
    }
}

pub fn setup() -> (Source, Journalist, Vec<u8>, Envelope) {
    let source = Source::new(&mut StdRng::seed_from_u64(666));
    let journalist = Journalist::new(&mut StdRng::seed_from_u64(666));
    let plaintext = b"super secret msg".to_vec();
    let envelope = encrypt(&source, &plaintext, &journalist);
    (source, journalist, plaintext, envelope)
}

pub fn bench_encrypt(c: &mut Criterion) {
    let (source, journalist, plaintext, _) = setup();

    c.benchmark_group("encrypt").bench_function(
        BenchmarkId::new("source_to_journalist", ""),
        |b| {
            b.iter(|| {
                encrypt(
                    &mut StdRng::seed_from_u64(666),
                    &source,
                    &plaintext,
                    &journalist,
                )
            });
        },
    );
}

pub fn bench_decrypt(c: &mut Criterion) {
    let (source, journalist, _, envelope) = setup();

    c.benchmark_group("decrypt").bench_function(
        BenchmarkId::new("journalist_from_source", ""),
        |b| {
            b.iter(|| decrypt(&journalist, &envelope));
        },
    );
}

pub fn bench_fetch(c: &mut Criterion) {
    unimplemented!()
}

criterion_group!(benches, bench_encrypt, bench_decrypt);
// criterion_group!(benches, bench_encrypt, bench_decrypt, bench_fetch);
criterion_main!(benches);
