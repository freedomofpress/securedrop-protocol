module Securedrop_protocol_minimal.Source
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// A source and their long-term key material (step 4).
/// A source's keys are fully determined by their passphrase: the fetch key,
/// APKE key, and PKE key are all derived from a master key via Argon2id and
/// a domain-separated KDF. Returning sources reconstruct the same keys by
/// calling [`Source::from_passphrase`] with the same passphrase.
type t_Source = {
  f_fetch_key:Securedrop_protocol_minimal.Keys.t_KeyPair
    Securedrop_protocol_minimal.Primitives.X25519.t_DHPrivateKey
    Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey;
  f_message_keys:Securedrop_protocol_minimal.Keys.t_MessageKeyBundle;
  f_passphrase:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_session:Securedrop_protocol_minimal.Keys.t_SessionStorage
}
