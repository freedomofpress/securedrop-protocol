module Securedrop_protocol_minimal.Wire.Core
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// A journalist's long-term public key material, as carried in the
/// [`WelcomeBundle`].
/// Combined with a one-time [`SignedKeyBundlePublic`] (fetched separately
/// by an ephemeral key request) to reconstruct a `JournalistPublicView` for
/// encryption.
type t_JournalistLongTermView = {
  f_vk:Securedrop_protocol_minimal.Schemes.Sign.t_VerifyingKey;
  f_signed_longterm_key_bundle:Securedrop_protocol_minimal.Wire.Bundle.t_SignedLongtermKeyBundle;
  f_nr_signature:Securedrop_protocol_minimal.Schemes.Sign.t_Signature
  Securedrop_protocol_minimal.Schemes.Sign.t_NewsroomOnJournalist
}

/// The newsroom "welcome bundle" (step 5): this is everything a sender needs to
/// begin - the newsroom verifying key, FPF's signature over it, and the roster
/// of journalists' long-term keys/signatures.
type t_WelcomeBundle = {
  f_newsroom_verifying_key:Securedrop_protocol_minimal.Schemes.Sign.t_VerifyingKey;
  f_fpf_sig:Securedrop_protocol_minimal.Schemes.Sign.t_Signature
  Securedrop_protocol_minimal.Schemes.Sign.t_FpfOnNewsroom;
  f_journalists:Alloc.Vec.t_Vec t_JournalistLongTermView Alloc.Alloc.t_Global
}

/// One journalist's one-time (ephemeral) key bundle. `vk` identifies which
/// journalist - the server consumes the bundle when it serves it.
type t_JournalistEphemeralKeys = {
  f_vk:Securedrop_protocol_minimal.Schemes.Sign.t_VerifyingKey;
  f_ephemeral:(Securedrop_protocol_minimal.Keys.Bundle.t_KeyBundlePublic &
    Securedrop_protocol_minimal.Schemes.Sign.t_Signature
    Securedrop_protocol_minimal.Schemes.Sign.t_JournalistEphemeralKey)
}

/// User (source or journalist) fetches message IDs
/// This corresponds to step 7 in the spec.
type t_MessageChallengeFetchRequest =
  | MessageChallengeFetchRequest : t_MessageChallengeFetchRequest

/// User fetches a specific message by ID
/// This corresponds to step 8 and 10 in the spec.
type t_MessageFetchRequest = { f_message_id:Uuid.t_Uuid }

type t_FetchResponse = {
  f_enc_id:t_Array u8 (mk_usize 32);
  f_pmgdh:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey
}

/// Server returns encrypted message IDs
/// This corresponds to step 7 in the spec.
type t_MessageChallengeFetchResponse = {
  f_count:usize;
  f_messages:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global
}

let impl_2: Core_models.Clone.t_Clone t_FetchResponse =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Core_models.Fmt.t_Debug t_FetchResponse

unfold
let impl_3 = impl_3'

let impl_FetchResponse__new
      (enc_id: t_Array u8 (mk_usize 32))
      (pmgdh: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey)
    : t_FetchResponse = { f_enc_id = enc_id; f_pmgdh = pmgdh } <: t_FetchResponse

/// The full submission `(C_S, X, Z)` sent from sender to server in step 6.
/// - `C_S = (ct^APKE, ct^PKE)`: the two ciphertexts
/// - `X = g^x`: ephemeral DH public key (hint)
/// - `Z = (pk_R^fetch)^x`: DH share for fetching (hint)
/// The server stores `(id, C_S, X, Z)` per message.
type t_Envelope = {
  f_ct_apke:Securedrop_protocol_minimal.Schemes.Message.t_MessageCiphertext;
  f_ct_pke:Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataCiphertext;
  f_mgdh_pubkey:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey;
  f_mgdh:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Core_models.Fmt.t_Debug t_Envelope

unfold
let impl_4 = impl_4'

let impl_5: Core_models.Clone.t_Clone t_Envelope =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_Envelope__cmessage_len (self: t_Envelope) : usize =
  Securedrop_protocol_minimal.Schemes.Message.impl_MessageCiphertext__len self.f_ct_apke

let impl_Envelope__cmetadata_len (self: t_Envelope) : usize =
  Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataCiphertext__len self.f_ct_pke

#push-options "--admit_smt_queries true"

let impl_Envelope__size_hint (self: t_Envelope) : usize =
  (Securedrop_protocol_minimal.Schemes.Message.impl_MessageCiphertext__len self.f_ct_apke <: usize) +!
  (Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataCiphertext__len self.f_ct_pke <: usize)

#pop-options
