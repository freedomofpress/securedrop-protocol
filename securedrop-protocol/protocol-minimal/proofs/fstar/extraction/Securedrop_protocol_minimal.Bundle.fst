module Securedrop_protocol_minimal.Bundle
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Rand_core in
  ()

type t_ChallengeInput = {
  f_message_id:t_Array u8 (mk_usize 16);
  f_mgdh_pubkey:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey;
  f_mgdh:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey
}

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

assume
val sort_by_id': entries: t_Slice t_FetchResponse -> t_Slice t_FetchResponse

unfold
let sort_by_id = sort_by_id'

#push-options "--admit_smt_queries true"

/// Note this is marked lax temporaily due to the `.expect()` panic freedom requirement
let make_response
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (challenge: t_ChallengeInput)
      (nr_id: t_Slice u8)
    : (v_R & t_FetchResponse) =
  let (tmp0: v_R), (out: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPrivateKey) =
    Securedrop_protocol_minimal.Primitives.Ristretto255.generate_random_scalar #v_R rng
  in
  let rng:v_R = tmp0 in
  let eph_sk:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPrivateKey = out in
  let shared_secret:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey =
    Securedrop_protocol_minimal.Primitives.Ristretto255.dh_shared_secret challenge.f_mgdh eph_sk
  in
  let key:t_Array u8 (mk_usize 32) =
    Core_models.Result.impl__unwrap #(t_Array u8 (mk_usize 32))
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Schemes.Challenge.derive_challenge_key shared_secret nr_id
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
  in
  let enc_mid:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Core_models.Result.impl__unwrap #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #Anyhow.t_Error
      (Securedrop_protocol_minimal.Schemes.Challenge.encrypt_message_id key
          (challenge.f_message_id <: t_Slice u8)
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
  in
  let kmid:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let kmid:t_Array u8 (mk_usize 32) =
    Core_models.Slice.impl__copy_from_slice #u8
      kmid
      (Alloc.Vec.impl_1__as_slice enc_mid <: t_Slice u8)
  in
  let pmgdh:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey =
    Securedrop_protocol_minimal.Primitives.Ristretto255.dh_shared_secret challenge.f_mgdh_pubkey
      eph_sk
  in
  let hax_temp_output:t_FetchResponse = { f_enc_id = kmid; f_pmgdh = pmgdh } <: t_FetchResponse in
  rng, hax_temp_output <: (v_R & t_FetchResponse)

#pop-options

/// Given a set of ciphertext bundles (C, X, Z) and their associated uuid,
/// compute a fixed-length set of "challenges" >= the number of SeverMessageStore entries.
/// A challenge is returned as a tuple of DH agreement outputs (or random data tuples of the same length).
/// For benchmarking purposes, supply the rng as a separable parameter, and allow the total number of expected responses to be specified as a paremeter (worst case performance
/// when the number of items in the server store approaches num total_responses.)
let compute_fetch_challenges
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (entries: t_Slice t_ChallengeInput)
      (total_responses: usize)
    : (v_R & Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global) =
  let responses:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #t_FetchResponse total_responses
  in
  let (tmp0: v_R), (out: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey) =
    Securedrop_protocol_minimal.Primitives.Ristretto255.random_dh_public_key #v_R rng
  in
  let rng:v_R = tmp0 in
  let (tmp0: v_R), (out: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey) =
    Securedrop_protocol_minimal.Primitives.Ristretto255.random_dh_public_key #v_R rng
  in
  let rng:v_R = tmp0 in
  let decoy:t_ChallengeInput =
    {
      f_message_id = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 16);
      f_mgdh = out;
      f_mgdh_pubkey = out
    }
    <:
    t_ChallengeInput
  in
  let (responses: Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global), (rng: v_R) =
    Rust_primitives.Hax.Folds.fold_range (mk_usize 0)
      total_responses
      (fun temp_0_ i ->
          let (responses: Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global), (rng: v_R) =
            temp_0_
          in
          let i:usize = i in
          (Alloc.Vec.impl_1__len #t_FetchResponse #Alloc.Alloc.t_Global responses <: usize) =. i
          <:
          bool)
      (responses, rng <: (Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global & v_R))
      (fun temp_0_ i ->
          let (responses: Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global), (rng: v_R) =
            temp_0_
          in
          let i:usize = i in
          let (rng: v_R), (response: t_FetchResponse) =
            if i <. (Core_models.Slice.impl__len #t_ChallengeInput entries <: usize)
            then
              let (tmp0: v_R), (out: t_FetchResponse) =
                make_response #v_R
                  rng
                  (entries.[ i ] <: t_ChallengeInput)
                  Securedrop_protocol_minimal.Keys.Newsroom.v_NR_ID
              in
              let rng:v_R = tmp0 in
              rng, out <: (v_R & t_FetchResponse)
            else
              let (tmp0: v_R), (out: t_FetchResponse) =
                make_response #v_R rng decoy Securedrop_protocol_minimal.Keys.Newsroom.v_NR_ID
              in
              let rng:v_R = tmp0 in
              rng, out <: (v_R & t_FetchResponse)
          in
          let responses:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global =
            Alloc.Vec.impl_1__push #t_FetchResponse #Alloc.Alloc.t_Global responses response
          in
          responses, rng <: (Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global & v_R))
  in
  let responses:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global =
    Alloc.Slice.impl__to_vec (sort_by_id (Alloc.Vec.impl_1__as_slice responses
            <:
            t_Slice t_FetchResponse)
        <:
        t_Slice t_FetchResponse)
  in
  let hax_temp_output:Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global = responses in
  rng, hax_temp_output <: (v_R & Alloc.Vec.t_Vec t_FetchResponse Alloc.Alloc.t_Global)

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

let impl__new
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

let impl_1__cmessage_len (self: t_Envelope) : usize =
  Securedrop_protocol_minimal.Schemes.Message.impl_MessageCiphertext__len self.f_ct_apke

let impl_1__cmetadata_len (self: t_Envelope) : usize =
  Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataCiphertext__len self.f_ct_pke

let impl_1__to_challenges (self: t_Envelope) (id: t_Array u8 (mk_usize 16)) : t_ChallengeInput =
  { f_message_id = id; f_mgdh_pubkey = self.f_mgdh_pubkey; f_mgdh = self.f_mgdh }
  <:
  t_ChallengeInput

#push-options "--admit_smt_queries true"

let impl_1__size_hint (self: t_Envelope) : usize =
  (Securedrop_protocol_minimal.Schemes.Message.impl_MessageCiphertext__len self.f_ct_apke <: usize) +!
  (Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataCiphertext__len self.f_ct_pke <: usize)

#pop-options
