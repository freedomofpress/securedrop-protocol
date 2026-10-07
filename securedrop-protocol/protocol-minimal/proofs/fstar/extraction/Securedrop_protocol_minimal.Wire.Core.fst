module Securedrop_protocol_minimal.Wire.Core
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// A journalist's long-term public key material, as carried in the
/// [`WelcomeBundle`].
/// Combined with a short-term [`SignedKeyBundlePublic`] (fetched separately
/// by an short term key request) to reconstruct a `JournalistPublicView` for
/// encryption.
type t_JournalistLongTermView = {
  f_vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_signed_longterm_key_bundle:Securedrop_protocol_minimal.Keys.t_SignedLongtermKeyBundle;
  f_nr_signature:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist
}

/// The newsroom "welcome bundle" (step 5): this is everything a sender needs to
/// begin - the newsroom verifying key, FPF's signature over it, and the roster
/// of journalists' long-term keys/signatures.
type t_WelcomeBundle = {
  f_newsroom_verifying_key:Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_fpf_sig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom;
  f_journalists:Alloc.Vec.t_Vec t_JournalistLongTermView Alloc.Alloc.t_Global
}

/// One journalist's short-term key bundle. `vk` identifies which
/// journalist
type t_JournalistShortTermKeys = {
  f_vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_short_term:Securedrop_protocol_minimal.Keys.t_SignedKeyBundlePublic
}

/// User (source or journalist) fetches message IDs
/// This corresponds to step 7 in the spec.
type t_MessageChallengeFetchRequest =
  | MessageChallengeFetchRequest : t_MessageChallengeFetchRequest

/// Server returns encrypted message IDs
/// This corresponds to step 7 in the spec.
type t_MessageChallengeFetchResponse = {
  f_count:usize;
  f_messages:Alloc.Vec.t_Vec Securedrop_protocol_minimal.Ciphertext.t_FetchResponse
    Alloc.Alloc.t_Global
}

/// User fetches a specific message by ID
/// This corresponds to step 8 and 10 in the spec.
type t_MessageFetchRequest = { f_message_id:Uuid.t_Uuid }
