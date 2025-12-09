module Securedrop_protocol.Keys.Journalist
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Rand_core in
  let open Securedrop_protocol.Primitives.Dh_akem in
  let open Securedrop_protocol.Primitives.Mlkem in
  let open Securedrop_protocol.Primitives.Xwing in
  ()

/// Journalists signing key pair
/// Signed by the newsroom
/// Long-term, same in 0.3
type t_JournalistSigningKeyPair = {
  f_vk:Securedrop_protocol.Sign.t_VerifyingKey;
  f_sk:Securedrop_protocol.Sign.t_SigningKey
}

let impl_JournalistSigningKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistSigningKeyPair =
  let
  (tmp0: v_R),
  (out: Core_models.Result.t_Result Securedrop_protocol.Sign.t_SigningKey Anyhow.t_Error) =
    Securedrop_protocol.Sign.impl_SigningKey__new #v_R rng
  in
  let rng:v_R = tmp0 in
  let sk:Securedrop_protocol.Sign.t_SigningKey =
    Core_models.Result.impl__expect #Securedrop_protocol.Sign.t_SigningKey
      #Anyhow.t_Error
      out
      "Signing key generation should succeed"
  in
  let vk:Securedrop_protocol.Sign.t_VerifyingKey = sk.Securedrop_protocol.Sign.f_vk in
  { f_vk = vk; f_sk = sk } <: t_JournalistSigningKeyPair

let impl_JournalistSigningKeyPair__sign (self: t_JournalistSigningKeyPair) (message: t_Slice u8)
    : Securedrop_protocol.Sign.t_Signature =
  Securedrop_protocol.Sign.impl_SigningKey__sign self.f_sk message

let impl_JournalistSigningKeyPair__verifying_key (self: t_JournalistSigningKeyPair)
    : Securedrop_protocol.Sign.t_VerifyingKey = self.f_vk

/// Journalist fetching key pair
/// Signed by the newsroom
/// Medium-term X25519, same in 0.3
type t_JournalistFetchKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.X25519.t_DHPublicKey;
  f_private_key:Securedrop_protocol.Primitives.X25519.t_DHPrivateKey
}

let impl_13: Core_models.Clone.t_Clone t_JournalistFetchKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_JournalistFetchKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistFetchKeyPair =
  let
  (private_key: Securedrop_protocol.Primitives.X25519.t_DHPrivateKey),
  (public_key: Securedrop_protocol.Primitives.X25519.t_DHPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol.Primitives.X25519.t_DHPublicKey)
      #Anyhow.t_Error
      (Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
          "securedrop_protocol::primitives::x25519::generate_dh_keypair::<&mut R>(&mut (rng))"
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
            Securedrop_protocol.Primitives.X25519.t_DHPublicKey) Anyhow.t_Error)
      "DH key generation failed"
  in
  { f_private_key = private_key; f_public_key = public_key } <: t_JournalistFetchKeyPair

/// Journalist medium term keypair
/// Signed by the newsroom
/// Only used in 0.2
type t_JournalistDHKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.X25519.t_DHPublicKey;
  f_private_key:Securedrop_protocol.Primitives.X25519.t_DHPrivateKey
}

let impl_14: Core_models.Clone.t_Clone t_JournalistDHKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_JournalistDHKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistDHKeyPair =
  let
  (private_key: Securedrop_protocol.Primitives.X25519.t_DHPrivateKey),
  (public_key: Securedrop_protocol.Primitives.X25519.t_DHPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol.Primitives.X25519.t_DHPublicKey)
      #Anyhow.t_Error
      (Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
          "securedrop_protocol::primitives::x25519::generate_dh_keypair::<&mut R>(&mut (rng))"
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
            Securedrop_protocol.Primitives.X25519.t_DHPublicKey) Anyhow.t_Error)
      "DH key generation failed"
  in
  { f_private_key = private_key; f_public_key = public_key } <: t_JournalistDHKeyPair

/// Journalist ephemeral KEM key pair
/// Signed by the journalist signing key
/// Only used in 0.2
type t_JournalistEphemeralKEMKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.t_PPKPublicKey;
  f_private_key:Securedrop_protocol.Primitives.t_PPKPrivateKey
}

let impl_JournalistEphemeralKEMKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistEphemeralKEMKeyPair =
  let
  (dh_private_key: Securedrop_protocol.Primitives.X25519.t_DHPrivateKey),
  (dh_public_key: Securedrop_protocol.Primitives.X25519.t_DHPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol.Primitives.X25519.t_DHPublicKey)
      #Anyhow.t_Error
      (Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
          "securedrop_protocol::primitives::x25519::generate_dh_keypair::<&mut R>(&mut (rng))"
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
            Securedrop_protocol.Primitives.X25519.t_DHPublicKey) Anyhow.t_Error)
      "DH key generation failed"
  in
  let private_key:Securedrop_protocol.Primitives.t_PPKPrivateKey =
    Securedrop_protocol.Primitives.impl_PPKPrivateKey__new dh_private_key
  in
  let public_key:Securedrop_protocol.Primitives.t_PPKPublicKey =
    Securedrop_protocol.Primitives.impl_PPKPublicKey__new dh_public_key
  in
  { f_private_key = private_key; f_public_key = public_key } <: t_JournalistEphemeralKEMKeyPair

/// Journalist ephemeral PKE key pair
/// Signed by the journalist signing key
/// Only used in 0.2
type t_JournalistEphemeralPKEKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.t_PPKPublicKey;
  f_private_key:Securedrop_protocol.Primitives.t_PPKPrivateKey
}

let impl_JournalistEphemeralPKEKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistEphemeralPKEKeyPair =
  let
  (dh_private_key: Securedrop_protocol.Primitives.X25519.t_DHPrivateKey),
  (dh_public_key: Securedrop_protocol.Primitives.X25519.t_DHPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol.Primitives.X25519.t_DHPublicKey)
      #Anyhow.t_Error
      (Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
          "securedrop_protocol::primitives::x25519::generate_dh_keypair::<&mut R>(&mut (rng))"
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
            Securedrop_protocol.Primitives.X25519.t_DHPublicKey) Anyhow.t_Error)
      "DH key generation failed"
  in
  let private_key:Securedrop_protocol.Primitives.t_PPKPrivateKey =
    Securedrop_protocol.Primitives.impl_PPKPrivateKey__new dh_private_key
  in
  let public_key:Securedrop_protocol.Primitives.t_PPKPublicKey =
    Securedrop_protocol.Primitives.impl_PPKPublicKey__new dh_public_key
  in
  { f_private_key = private_key; f_public_key = public_key } <: t_JournalistEphemeralPKEKeyPair

/// Journalist ephemeral DH-AKEM keypair
/// Signed by the journalist signing key
/// Only used in 0.2
type t_JournalistEphemeralDHKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.X25519.t_DHPublicKey;
  f_private_key:Securedrop_protocol.Primitives.X25519.t_DHPrivateKey
}

let impl_JournalistEphemeralDHKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistEphemeralDHKeyPair =
  let
  (private_key: Securedrop_protocol.Primitives.X25519.t_DHPrivateKey),
  (public_key: Securedrop_protocol.Primitives.X25519.t_DHPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol.Primitives.X25519.t_DHPublicKey)
      #Anyhow.t_Error
      (Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
          "securedrop_protocol::primitives::x25519::generate_dh_keypair::<&mut R>(&mut (rng))"
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
            Securedrop_protocol.Primitives.X25519.t_DHPublicKey) Anyhow.t_Error)
      "DH key generation failed"
  in
  { f_private_key = private_key; f_public_key = public_key } <: t_JournalistEphemeralDHKeyPair

/// Journalist message encryption PSK (used for PQ secret)
/// One-time key
/// $J_epq$ in the specification.
type t_JournalistOneTimeMessagePQKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey;
  f_private_key:Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_15': Core_models.Fmt.t_Debug t_JournalistOneTimeMessagePQKeyPair

unfold
let impl_15 = impl_15'

let impl_16: Core_models.Clone.t_Clone t_JournalistOneTimeMessagePQKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_JournalistOneTimeMessagePQKeyPair__new
      (pubkey: Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey)
      (priv_key: Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey)
    : t_JournalistOneTimeMessagePQKeyPair =
  { f_public_key = pubkey; f_private_key = priv_key } <: t_JournalistOneTimeMessagePQKeyPair

/// Generate a new one-time message PQ key pair
let impl_JournalistOneTimeMessagePQKeyPair__generate
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistOneTimeMessagePQKeyPair =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey &
        Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.Mlkem.generate_mlkem768_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  let
  (private_key: Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey),
  (public_key: Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey &
        Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey)
      #Anyhow.t_Error
      out
      "MLKEM-768 key generation failed"
  in
  { f_private_key = private_key; f_public_key = public_key } <: t_JournalistOneTimeMessagePQKeyPair

/// Journalist message encryption keypair
/// One-time key
/// $J_epke$ in the specification.
type t_JournalistOneTimeMessageClassicalKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_private_key:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_17': Core_models.Fmt.t_Debug t_JournalistOneTimeMessageClassicalKeyPair

unfold
let impl_17 = impl_17'

let impl_18: Core_models.Clone.t_Clone t_JournalistOneTimeMessageClassicalKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_JournalistOneTimeMessageClassicalKeyPair__new
      (pubkey: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
      (priv_key: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey)
    : t_JournalistOneTimeMessageClassicalKeyPair =
  { f_public_key = pubkey; f_private_key = priv_key } <: t_JournalistOneTimeMessageClassicalKeyPair

/// Generate a new one-time message classical key pair
let impl_JournalistOneTimeMessageClassicalKeyPair__generate
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistOneTimeMessageClassicalKeyPair =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey &
        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.Dh_akem.generate_dh_akem_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  let
  (private_key: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey),
  (public_key: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey &
        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
      #Anyhow.t_Error
      out
      "DH-AKEM key generation failed"
  in
  { f_private_key = private_key; f_public_key = public_key }
  <:
  t_JournalistOneTimeMessageClassicalKeyPair

/// Journalist metadata keypair
/// One-time key
/// $J_emd$ in the specification.
type t_JournalistOneTimeMetadataKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey;
  f_private_key:Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_19': Core_models.Fmt.t_Debug t_JournalistOneTimeMetadataKeyPair

unfold
let impl_19 = impl_19'

let impl_20: Core_models.Clone.t_Clone t_JournalistOneTimeMetadataKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_JournalistOneTimeMetadataKeyPair__new
      (pubkey: Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey)
      (priv_key: Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey)
    : t_JournalistOneTimeMetadataKeyPair =
  { f_public_key = pubkey; f_private_key = priv_key } <: t_JournalistOneTimeMetadataKeyPair

/// Generate a new metadata keypair
let impl_JournalistOneTimeMetadataKeyPair__generate
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistOneTimeMetadataKeyPair =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey &
        Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.Xwing.generate_xwing_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  let
  (private_key: Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey),
  (public_key: Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey &
        Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey)
      #Anyhow.t_Error
      out
      "XWING key generation failed"
  in
  { f_private_key = private_key; f_public_key = public_key } <: t_JournalistOneTimeMetadataKeyPair

/// Journalist medium or long-term DH-AKEM key used for sending replies
type t_JournalistReplyClassicalKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_private_key:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_21': Core_models.Fmt.t_Debug t_JournalistReplyClassicalKeyPair

unfold
let impl_21 = impl_21'

let impl_22: Core_models.Clone.t_Clone t_JournalistReplyClassicalKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_JournalistReplyClassicalKeyPair__new
      (pubkey: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
      (priv_key: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey)
    : t_JournalistReplyClassicalKeyPair =
  { f_public_key = pubkey; f_private_key = priv_key } <: t_JournalistReplyClassicalKeyPair

/// Generate a new medium/long-term keypair for sending replies
let impl_JournalistReplyClassicalKeyPair__generate
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistReplyClassicalKeyPair =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result
      (Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey &
        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) Anyhow.t_Error) =
    Securedrop_protocol.Primitives.Dh_akem.generate_dh_akem_keypair #v_R rng
  in
  let rng:v_R = tmp0 in
  let
  (private_key: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey),
  (public_key: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey &
        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
      #Anyhow.t_Error
      out
      "DH-AKEM key generation failed"
  in
  { f_private_key = private_key; f_public_key = public_key } <: t_JournalistReplyClassicalKeyPair

/// One-time public keys for a journalist (without signature)
/// This struct contains just the one-time public keys that need to be signed.
/// Used for creating the message to sign in Step 3.2.
/// Updated for 0.3 spec with new key types:
/// - J_{epq} (MLKEM-768) for message enc PSK (one-time)
/// - J_{epke} (DH-AKEM) for message enc (one-time)
/// - J_{emd} (XWING) for metadata enc (one-time)
/// - Note that all the one-time keys are for messages received
/// TODO: Use JournalistOneTimeKeypairs::pubkeys()
type t_JournalistOneTimePublicKeys = {
  f_one_time_message_pq_pk:Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey;
  f_one_time_message_pk:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_one_time_metadata_pk:Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_23': Core_models.Fmt.t_Debug t_JournalistOneTimePublicKeys

unfold
let impl_23 = impl_23'

let impl_24: Core_models.Clone.t_Clone t_JournalistOneTimePublicKeys =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Convert the one-time public keys to a byte array for signing
/// Returns a byte array containing the concatenated public keys:
/// - one_time_message_pq_pk (1184 bytes) - MLKEM-768
/// - one_time_message_pk (32 bytes) - DH-AKEM
/// - one_time_metadata_pk (1216 bytes) - XWING
/// Total: 2432 bytes
let impl_JournalistOneTimePublicKeys__into_bytes (self: t_JournalistOneTimePublicKeys)
    : t_Array u8 (mk_usize 2432) =
  let bytes:t_Array u8 (mk_usize 2432) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 2432) in
  let bytes:t_Array u8 (mk_usize 2432) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_range bytes
      ({ Core_models.Ops.Range.f_start = mk_usize 0; Core_models.Ops.Range.f_end = mk_usize 1184 }
        <:
        Core_models.Ops.Range.t_Range usize)
      (Core_models.Slice.impl__copy_from_slice #u8
          (bytes.[ {
                Core_models.Ops.Range.f_start = mk_usize 0;
                Core_models.Ops.Range.f_end = mk_usize 1184
              }
              <:
              Core_models.Ops.Range.t_Range usize ]
            <:
            t_Slice u8)
          (Securedrop_protocol.Primitives.Mlkem.impl_MLKEM768PublicKey__as_bytes self
                .f_one_time_message_pq_pk
            <:
            t_Slice u8)
        <:
        t_Slice u8)
  in
  let bytes:t_Array u8 (mk_usize 2432) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_range bytes
      ({
          Core_models.Ops.Range.f_start = mk_usize 1184;
          Core_models.Ops.Range.f_end = mk_usize 1216
        }
        <:
        Core_models.Ops.Range.t_Range usize)
      (Core_models.Slice.impl__copy_from_slice #u8
          (bytes.[ {
                Core_models.Ops.Range.f_start = mk_usize 1184;
                Core_models.Ops.Range.f_end = mk_usize 1216
              }
              <:
              Core_models.Ops.Range.t_Range usize ]
            <:
            t_Slice u8)
          (Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPublicKey__as_bytes self
                .f_one_time_message_pk
            <:
            t_Slice u8)
        <:
        t_Slice u8)
  in
  let bytes:t_Array u8 (mk_usize 2432) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_range bytes
      ({
          Core_models.Ops.Range.f_start = mk_usize 1216;
          Core_models.Ops.Range.f_end = mk_usize 2432
        }
        <:
        Core_models.Ops.Range.t_Range usize)
      (Core_models.Slice.impl__copy_from_slice #u8
          (bytes.[ {
                Core_models.Ops.Range.f_start = mk_usize 1216;
                Core_models.Ops.Range.f_end = mk_usize 2432
              }
              <:
              Core_models.Ops.Range.t_Range usize ]
            <:
            t_Slice u8)
          (Securedrop_protocol.Primitives.Xwing.impl_XWingPublicKey__as_bytes self
                .f_one_time_metadata_pk
            <:
            t_Slice u8)
        <:
        t_Slice u8)
  in
  bytes

/// One-time public key set for a journalist
type t_JournalistOneTimeKeyBundle = {
  f_public_keys:t_JournalistOneTimePublicKeys;
  f_signature:Securedrop_protocol.Sign.t_Signature
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_25': Core_models.Fmt.t_Debug t_JournalistOneTimeKeyBundle

unfold
let impl_25 = impl_25'

let impl_26: Core_models.Clone.t_Clone t_JournalistOneTimeKeyBundle =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

type t_JournalistLongtermPublicKeys = {
  f_reply_key:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_fetch_key:Securedrop_protocol.Primitives.X25519.t_DHPublicKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_27': Core_models.Fmt.t_Debug t_JournalistLongtermPublicKeys

unfold
let impl_27 = impl_27'

let impl_28: Core_models.Clone.t_Clone t_JournalistLongtermPublicKeys =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Convert public keys to a byte array for signing
/// Returns a byte array containing the concatenated public keys:
/// - fetch_key (32 bytes) - DH
/// - long-term reply (32 bytes) - DH-AKEM
/// Total: 64 bytes
let impl_JournalistLongtermPublicKeys__into_bytes (self: t_JournalistLongtermPublicKeys)
    : t_Array u8 (mk_usize 64) =
  let bytes:t_Array u8 (mk_usize 64) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 64) in
  let bytes:t_Array u8 (mk_usize 64) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_range bytes
      ({ Core_models.Ops.Range.f_start = mk_usize 0; Core_models.Ops.Range.f_end = mk_usize 32 }
        <:
        Core_models.Ops.Range.t_Range usize)
      (Core_models.Slice.impl__copy_from_slice #u8
          (bytes.[ {
                Core_models.Ops.Range.f_start = mk_usize 0;
                Core_models.Ops.Range.f_end = mk_usize 32
              }
              <:
              Core_models.Ops.Range.t_Range usize ]
            <:
            t_Slice u8)
          (Securedrop_protocol.Primitives.X25519.impl_DHPublicKey__into_bytes self.f_fetch_key
            <:
            t_Slice u8)
        <:
        t_Slice u8)
  in
  let bytes:t_Array u8 (mk_usize 64) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_range bytes
      ({ Core_models.Ops.Range.f_start = mk_usize 32; Core_models.Ops.Range.f_end = mk_usize 64 }
        <:
        Core_models.Ops.Range.t_Range usize)
      (Core_models.Slice.impl__copy_from_slice #u8
          (bytes.[ {
                Core_models.Ops.Range.f_start = mk_usize 32;
                Core_models.Ops.Range.f_end = mk_usize 64
              }
              <:
              Core_models.Ops.Range.t_Range usize ]
            <:
            t_Slice u8)
          (Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPublicKey__as_bytes self.f_reply_key
            <:
            t_Slice u8)
        <:
        t_Slice u8)
  in
  bytes

/// One-time keystore (public and private) for a journalist
/// TODO: improve/refactor with OneTimeKeyBundle
/// TODO: use native hpke-rs types
type t_JournalistOneTimeKeypairs = {
  f_dh_akem:t_JournalistOneTimeMessageClassicalKeyPair;
  f_pq_kem_psk:t_JournalistOneTimeMessagePQKeyPair;
  f_metadata:t_JournalistOneTimeMetadataKeyPair
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_29': Core_models.Fmt.t_Debug t_JournalistOneTimeKeypairs

unfold
let impl_29 = impl_29'

let impl_30: Core_models.Clone.t_Clone t_JournalistOneTimeKeypairs =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_JournalistOneTimeKeypairs__new
      (dh_key: t_JournalistOneTimeMessageClassicalKeyPair)
      (pq_kem_psk_key: t_JournalistOneTimeMessagePQKeyPair)
      (metadata_key: t_JournalistOneTimeMetadataKeyPair)
    : t_JournalistOneTimeKeypairs =
  { f_dh_akem = dh_key; f_pq_kem_psk = pq_kem_psk_key; f_metadata = metadata_key }
  <:
  t_JournalistOneTimeKeypairs

/// Generate a key bundle
let impl_JournalistOneTimeKeypairs__generate
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : t_JournalistOneTimeKeypairs =
  let dh_key:t_JournalistOneTimeMessageClassicalKeyPair =
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "securedrop_protocol::keys::journalist::impl_JournalistOneTimeMessageClassicalKeyPair__generate::<\n &mut R,\n >(&mut (rng))"

  in
  let pq_kem_psk_key:t_JournalistOneTimeMessagePQKeyPair =
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "securedrop_protocol::keys::journalist::impl_JournalistOneTimeMessagePQKeyPair__generate::<\n &mut R,\n >(&mut (rng))"

  in
  let metadata_key:t_JournalistOneTimeMetadataKeyPair =
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "securedrop_protocol::keys::journalist::impl_JournalistOneTimeMetadataKeyPair__generate::<\n &mut R,\n >(&mut (rng))"

  in
  impl_JournalistOneTimeKeypairs__new dh_key pq_kem_psk_key metadata_key

let impl_JournalistOneTimeKeypairs__pubkeys (self: t_JournalistOneTimeKeypairs)
    : t_JournalistOneTimePublicKeys =
  {
    f_one_time_message_pq_pk
    =
    Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey
      #FStar.Tactics.Typeclasses.solve
      self.f_pq_kem_psk.f_public_key;
    f_one_time_message_pk
    =
    Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
      #FStar.Tactics.Typeclasses.solve
      self.f_dh_akem.f_public_key;
    f_one_time_metadata_pk
    =
    Core_models.Clone.f_clone #Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey
      #FStar.Tactics.Typeclasses.solve
      self.f_metadata.f_public_key
  }
  <:
  t_JournalistOneTimePublicKeys

/// Journalist enrollment key bundle for 0.3 spec
/// This bundle is used to enroll a journalist into the system.
/// Long-term keys for a journalist
type t_JournalistEnrollmentKeyBundle = {
  f_signing_key:Securedrop_protocol.Sign.t_VerifyingKey;
  f_public_keys:t_JournalistLongtermPublicKeys;
  f_self_signature:Securedrop_protocol.Sign.t_SelfSignature
}

let impl_31: Core_models.Clone.t_Clone t_JournalistEnrollmentKeyBundle =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }
