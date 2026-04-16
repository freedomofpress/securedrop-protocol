module Securedrop_protocol_minimal.Wire.Core
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Source fetches keys for the newsroom
/// This is the first request in step 5 of the spec.
type t_SourceNewsroomKeyRequest = | SourceNewsroomKeyRequest : t_SourceNewsroomKeyRequest

/// Newsroom returns their keys and proof of onboarding.
/// This is the first response in step 5 of the spec.
type t_SourceNewsroomKeyResponse = {
  f_newsroom_verifying_key:Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_fpf_sig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom
}

/// Source fetches journalist keys for the newsroom
/// This is part of step 5 in the spec.
/// Note: This isn't currently written down in the spec, but
/// should occur right before the server provides a long-term
/// key and an ephmeral key bundle for the journalist.
type t_SourceJournalistKeyRequest = | SourceJournalistKeyRequest : t_SourceJournalistKeyRequest

/// Server returns journalist long-term keys and ephemeral keys
/// This is the second part of step 5 in the spec.
/// Updated for 0.3 spec with new key types:
/// - ephemeral_dh_pk: MLKEM-768 for message enc PSK (one-time)
/// - ephemeral_kem_pk: DH-AKEM for message enc (one-time)
/// - ephemeral_pke_pk: XWING for metadata enc (one-time)
/// TODO: this may be split into 2 responses, one that contains
/// static keys and one that contains one-time keys
type t_SourceJournalistKeyResponse = {
  f_journalist:Securedrop_protocol_minimal.Journalist.t_JournalistPublicView;
  f_nr_signature:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_NewsroomOnJournalist
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
