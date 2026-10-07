module Securedrop_protocol_minimal.Keys
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  let open Securedrop_protocol_minimal.Message in
  let open Securedrop_protocol_minimal.Metadata in
  let open Securedrop_protocol_minimal.Sign in
  ()

/// Generic KeyPair
type t_KeyPair (v_SK: Type0) (v_PK: Type0) = {
  f_sk:v_SK;
  f_pk:v_PK
}

/// The public keys that make up one short-term key bundle
type t_KeyBundlePublic = {
  f_apke_pk:Securedrop_protocol_minimal.Message.t_MessagePublicKey;
  f_metadata_pk:Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_9': Core_models.Fmt.t_Debug t_KeyBundlePublic

unfold
let impl_9 = impl_9'

let impl_10: Core_models.Clone.t_Clone t_KeyBundlePublic =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Serialize the bundle public keys in canonical byte order.
/// Layout: `pk_{J,i}^{APKE_E}(DHKEM) || pk_{J,i}^{APKE_E}(ML-KEM) || pk_{J,i}^{PKE_E}(X-Wing)`
let impl_KeyBundlePublic__as_bytes (self: t_KeyBundlePublic)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (Alloc.Vec.impl_1__as_slice (Securedrop_protocol_minimal.Message.impl_MessagePublicKey__as_bytes
              self.f_apke_pk
            <:
            Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        <:
        t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (Securedrop_protocol_minimal.Metadata.impl_MetadataPublicKey__as_bytes self.f_metadata_pk
        <:
        t_Slice u8)
  in
  out

type t_MessageKeyBundle = {
  f_apke:Securedrop_protocol_minimal.Message.t_MessageKeyPair;
  f_metadata_kp:Securedrop_protocol_minimal.Metadata.t_MetadataKeyPair
}

let impl_MessageKeyBundle__new
      (apke: Securedrop_protocol_minimal.Message.t_MessageKeyPair)
      (metadata_kp: Securedrop_protocol_minimal.Metadata.t_MetadataKeyPair)
    : t_MessageKeyBundle = { f_apke = apke; f_metadata_kp = metadata_kp } <: t_MessageKeyBundle

let impl_MessageKeyBundle__public (self: t_MessageKeyBundle) : t_KeyBundlePublic =
  {
    f_apke_pk
    =
    Core_models.Clone.f_clone #Securedrop_protocol_minimal.Message.t_MessagePublicKey
      #FStar.Tactics.Typeclasses.solve
      (Securedrop_protocol_minimal.Message.impl_MessageKeyPair__public_key self.f_apke
        <:
        Securedrop_protocol_minimal.Message.t_MessagePublicKey);
    f_metadata_pk
    =
    Core_models.Clone.f_clone #Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey
      #FStar.Tactics.Typeclasses.solve
      (Securedrop_protocol_minimal.Metadata.impl_MetadataKeyPair__public_key self.f_metadata_kp
        <:
        Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey)
  }
  <:
  t_KeyBundlePublic

/// Seconds since the Unix epoch
type t_Timestamp = | Timestamp : u64 -> t_Timestamp

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_11': Core_models.Fmt.t_Debug t_Timestamp

unfold
let impl_11 = impl_11'

let impl_12: Core_models.Clone.t_Clone t_Timestamp =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_13': Core_models.Marker.t_Copy t_Timestamp

unfold
let impl_13 = impl_13'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_14': Core_models.Marker.t_StructuralPartialEq t_Timestamp

unfold
let impl_14 = impl_14'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_15': Core_models.Cmp.t_PartialEq t_Timestamp t_Timestamp

unfold
let impl_15 = impl_15'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_16': Core_models.Cmp.t_Eq t_Timestamp

unfold
let impl_16 = impl_16'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_17': Core_models.Cmp.t_PartialOrd t_Timestamp t_Timestamp

unfold
let impl_17 = impl_17'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_18': Core_models.Cmp.t_Ord t_Timestamp

unfold
let impl_18 = impl_18'

/// Constant length of an epoch in seconds
let v_EPOCH_LEN: u64 = (mk_u64 60 *! mk_u64 60 <: u64) *! mk_u64 24

/// Index of a short-term key epoch, anchored to the Unix epoch:
/// epoch `n` covers `[n * EPOCH_LEN, (n + 1) * EPOCH_LEN)`.
type t_Epoch = | Epoch : u64 -> t_Epoch

/// The public half of an short-term key bundle together with the journalist's
/// self-signature over it.
type t_SignedKeyBundlePublic = {
  f_bundle:t_KeyBundlePublic;
  f_epoch:t_Epoch;
  f_selfsig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_JournalistShortTermKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Core_models.Fmt.t_Debug t_SignedKeyBundlePublic

unfold
let impl_7 = impl_7'

let impl_8: Core_models.Clone.t_Clone t_SignedKeyBundlePublic =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_SignedKeyBundlePublic__new
      (bundle: t_KeyBundlePublic)
      (epoch: t_Epoch)
      (selfsig:
          Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_JournalistShortTermKey)
    : t_SignedKeyBundlePublic =
  { f_bundle = bundle; f_epoch = epoch; f_selfsig = selfsig } <: t_SignedKeyBundlePublic

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_19': Core_models.Fmt.t_Debug t_Epoch

unfold
let impl_19 = impl_19'

let impl_20: Core_models.Clone.t_Clone t_Epoch =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_21': Core_models.Marker.t_Copy t_Epoch

unfold
let impl_21 = impl_21'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_22': Core_models.Marker.t_StructuralPartialEq t_Epoch

unfold
let impl_22 = impl_22'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_23': Core_models.Cmp.t_PartialEq t_Epoch t_Epoch

unfold
let impl_23 = impl_23'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_24': Core_models.Cmp.t_Eq t_Epoch

unfold
let impl_24 = impl_24'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_25': Core_models.Cmp.t_PartialOrd t_Epoch t_Epoch

unfold
let impl_25 = impl_25'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_26': Core_models.Cmp.t_Ord t_Epoch

unfold
let impl_26 = impl_26'

let impl_Epoch__ENCODED_LEN: usize = mk_usize 8

/// Epoch that `now` falls in.
let impl_Epoch__containing (now: t_Timestamp) : t_Epoch = Epoch (now._0 /! v_EPOCH_LEN) <: t_Epoch

/// Whether `now` falls within this timestamp.
let impl_Epoch__contains (self: t_Epoch) (now: t_Timestamp) : bool =
  (impl_Epoch__containing now <: t_Epoch) =. self

/// Start of the epoch (inclusive).
let impl_Epoch__not_before (self: t_Epoch) : t_Timestamp =
  Timestamp (Core_models.Num.impl_u64__saturating_mul self._0 v_EPOCH_LEN) <: t_Timestamp

/// End of the epoch (exclusive).
let impl_Epoch__not_after (self: t_Epoch) : t_Timestamp =
  Timestamp
  (Core_models.Num.impl_u64__saturating_mul (Core_models.Num.impl_u64__saturating_add self._0
          (mk_u64 1)
        <:
        u64)
      v_EPOCH_LEN)
  <:
  t_Timestamp

/// Whether this epoch is valid at `now`, allowing for a `skew` in seconds
let impl_Epoch__is_valid_at (self: t_Epoch) (now: t_Timestamp) (skew: u64) : bool =
  let start:t_Epoch =
    impl_Epoch__containing (Timestamp (Core_models.Num.impl_u64__saturating_sub now._0 skew <: u64)
        <:
        t_Timestamp)
  in
  let v_end:t_Epoch =
    impl_Epoch__containing (Timestamp (Core_models.Num.impl_u64__saturating_add now._0 skew <: u64)
        <:
        t_Timestamp)
  in
  Core_models.Cmp.f_ge #t_Epoch #t_Epoch #FStar.Tactics.Typeclasses.solve self start &&
  Core_models.Cmp.f_le #t_Epoch #t_Epoch #FStar.Tactics.Typeclasses.solve self v_end

/// Canonical encoding of epoch index as u64 BE.
let impl_Epoch__as_bytes (self: t_Epoch) : t_Array u8 (mk_usize 8) =
  Core_models.Num.impl_u64__to_be_bytes self._0

let impl_SignedKeyBundlePublic__make_signed_bytes (bundle: t_KeyBundlePublic) (epoch: t_Epoch)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (Alloc.Vec.impl_1__as_slice (impl_KeyBundlePublic__as_bytes bundle
            <:
            Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        <:
        t_Slice u8)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (impl_Epoch__as_bytes epoch <: t_Slice u8)
  in
  out

let impl_SignedKeyBundlePublic__signed_bytes (self: t_SignedKeyBundlePublic)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  impl_SignedKeyBundlePublic__make_signed_bytes self.f_bundle self.f_epoch

let impl_Epoch__from_bytes (bytes: t_Array u8 (mk_usize 8)) : t_Epoch =
  Epoch (Core_models.Num.impl_u64__from_be_bytes bytes) <: t_Epoch

type t_SignedMessageKeyBundle = {
  f_bundle:t_MessageKeyBundle;
  f_epoch:t_Epoch;
  f_selfsig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_JournalistShortTermKey
}

type t_LongtermKeyBundle = {
  f_apke:Securedrop_protocol_minimal.Message.t_MessagePublicKey;
  f_fetch_pk:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_27': Core_models.Fmt.t_Debug t_LongtermKeyBundle

unfold
let impl_27 = impl_27'

let impl_28: Core_models.Clone.t_Clone t_LongtermKeyBundle =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_LongtermKeyBundle__LEN: usize =
  Securedrop_protocol_minimal.Message.impl_MessagePublicKey__LEN +!
  Securedrop_protocol_minimal.Primitives.Ristretto255.impl_DHPublicKey__LEN

let impl_LongtermKeyBundle__new
      (apke: Securedrop_protocol_minimal.Message.t_MessagePublicKey)
      (fetch_pk: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey)
    : t_LongtermKeyBundle = { f_apke = apke; f_fetch_pk = fetch_pk } <: t_LongtermKeyBundle

/// Serialize long-term public keys into the canonical byte encoding.
/// Byte layout (per spec §3.1): `pk_J^APKE || pk_J^fetch`
/// where `pk_J^APKE = pk_J^AKEM (DH-AKEM) || pk_J^PQ (ML-KEM)`
let impl_LongtermKeyBundle__as_bytes (self: t_LongtermKeyBundle) : t_Array u8 (mk_usize 1248) =
  let apke_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Securedrop_protocol_minimal.Message.impl_MessagePublicKey__as_bytes self.f_apke
  in
  let fetch_bytes:t_Array u8 (mk_usize 32) =
    Securedrop_protocol_minimal.Primitives.Ristretto255.impl_DHPublicKey__into_bytes self.f_fetch_pk
  in
  let pubkey_bytes:t_Array u8 (mk_usize 1248) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 1248)
  in
  let pubkey_bytes:t_Array u8 (mk_usize 1248) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_range_to pubkey_bytes
      ({
          Core_models.Ops.Range.f_end
          =
          Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global apke_bytes <: usize
        }
        <:
        Core_models.Ops.Range.t_RangeTo usize)
      (Core_models.Slice.impl__copy_from_slice #u8
          (pubkey_bytes.[ {
                Core_models.Ops.Range.f_end
                =
                Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global apke_bytes <: usize
              }
              <:
              Core_models.Ops.Range.t_RangeTo usize ]
            <:
            t_Slice u8)
          (Alloc.Vec.impl_1__as_slice apke_bytes <: t_Slice u8)
        <:
        t_Slice u8)
  in
  let pubkey_bytes:t_Array u8 (mk_usize 1248) =
    Rust_primitives.Hax.Monomorphized_update_at.update_at_range_from pubkey_bytes
      ({
          Core_models.Ops.Range.f_start
          =
          Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global apke_bytes <: usize
        }
        <:
        Core_models.Ops.Range.t_RangeFrom usize)
      (Core_models.Slice.impl__copy_from_slice #u8
          (pubkey_bytes.[ {
                Core_models.Ops.Range.f_start
                =
                Alloc.Vec.impl_1__len #u8 #Alloc.Alloc.t_Global apke_bytes <: usize
              }
              <:
              Core_models.Ops.Range.t_RangeFrom usize ]
            <:
            t_Slice u8)
          (fetch_bytes <: t_Slice u8)
        <:
        t_Slice u8)
  in
  pubkey_bytes

type t_SignedLongtermKeyBundle = {
  f_bundle:t_LongtermKeyBundle;
  f_selfsig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_29': Core_models.Fmt.t_Debug t_SignedLongtermKeyBundle

unfold
let impl_29 = impl_29'

let impl_30: Core_models.Clone.t_Clone t_SignedLongtermKeyBundle =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_SignedLongtermKeyBundle__new
      (bundle: t_LongtermKeyBundle)
      (selfsig:
          Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey)
    : t_SignedLongtermKeyBundle =
  { f_bundle = bundle; f_selfsig = selfsig } <: t_SignedLongtermKeyBundle

let impl_SignedLongtermKeyBundle__as_bytes (self: t_SignedLongtermKeyBundle)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let bundle_bytes:t_Array u8 (mk_usize 1248) = impl_LongtermKeyBundle__as_bytes self.f_bundle in
  let sig_bytes:t_Array u8 (mk_usize 64) =
    Securedrop_protocol_minimal.Sign.impl_7__as_bytes #Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey
      self.f_selfsig
  in
  let pubkey_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #u8
      ((Core_models.Slice.impl__len #u8 (bundle_bytes <: t_Slice u8) <: usize) +!
        (Core_models.Slice.impl__len #u8 (sig_bytes <: t_Slice u8) <: usize)
        <:
        usize)
  in
  let pubkey_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      pubkey_bytes
      (bundle_bytes <: t_Slice u8)
  in
  let pubkey_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      pubkey_bytes
      (sig_bytes <: t_Slice u8)
  in
  pubkey_bytes

let impl_SignedLongtermKeyBundle__bundle_bytes (self: t_SignedLongtermKeyBundle)
    : t_Array u8 (mk_usize 1248) = impl_LongtermKeyBundle__as_bytes self.f_bundle

let impl_SignedLongtermKeyBundle__apke (self: t_SignedLongtermKeyBundle)
    : Securedrop_protocol_minimal.Message.t_MessagePublicKey = self.f_bundle.f_apke

let impl_SignedLongtermKeyBundle__fetch_pk (self: t_SignedLongtermKeyBundle)
    : Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey = self.f_bundle.f_fetch_pk

type t_Enrollment = {
  f_bundle:t_SignedLongtermKeyBundle;
  f_verification_key:Securedrop_protocol_minimal.Sign.t_VerifyingKey
}

let impl_33: Core_models.Clone.t_Clone t_Enrollment =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_34': Core_models.Fmt.t_Debug t_Enrollment

unfold
let impl_34 = impl_34'

type t_SessionStorage = {
  f_fpf_key:Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_nr_key:Core_models.Option.t_Option Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_fpf_signature:Core_models.Option.t_Option
  (Securedrop_protocol_minimal.Sign.t_Signature Securedrop_protocol_minimal.Sign.t_FpfOnNewsroom)
}

/// A key pair for FPF (Freedom of the Press Foundation).
type t_FPFKeyPair = {
  f_sk:Securedrop_protocol_minimal.Sign.t_SigningKey;
  f_vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey
}

/// Generate a new FPF key pair.
/// # Errors
/// Returns an error if the key generation fails.
let impl_FPFKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error) =
  let
  (tmp0: v_R),
  (out: Core_models.Result.t_Result Securedrop_protocol_minimal.Sign.t_SigningKey Anyhow.t_Error) =
    Securedrop_protocol_minimal.Sign.impl_SigningKey__new #v_R rng
  in
  let rng:v_R = tmp0 in
  match
    out <: Core_models.Result.t_Result Securedrop_protocol_minimal.Sign.t_SigningKey Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok sk ->
    let vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey =
      sk.Securedrop_protocol_minimal.Sign.f_vk
    in
    let hax_temp_output:Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error =
      Core_models.Result.Result_Ok ({ f_sk = sk; f_vk = vk } <: t_FPFKeyPair)
      <:
      Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error
    in
    rng, hax_temp_output <: (v_R & Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error)

/// Returns the verification key.
let impl_FPFKeyPair__verifying_key (self: t_FPFKeyPair)
    : Securedrop_protocol_minimal.Sign.t_VerifyingKey = self.f_vk

/// Sign `msg` in domain `D` using the FPF signing key.
let impl_FPFKeyPair__sign
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i0:
          Securedrop_protocol_minimal.Sign.t_DomainTag v_D)
      (self: t_FPFKeyPair)
      (msg: t_Slice u8)
    : Securedrop_protocol_minimal.Sign.t_Signature v_D =
  Securedrop_protocol_minimal.Sign.impl_SigningKey__sign #v_D self.f_sk msg

/// The FPF signing key used as a secret.
let impl_FPFKeyPair__as_bytes (self: t_FPFKeyPair) : t_Array u8 (mk_usize 32) =
  Securedrop_protocol_minimal.Sign.impl_SigningKey__as_bytes self.f_sk

/// Reconstruct an [`FPFKeyPair`] from its secret.
let impl_FPFKeyPair__from_bytes (seed: t_Array u8 (mk_usize 32)) : t_FPFKeyPair =
  let sk:Securedrop_protocol_minimal.Sign.t_SigningKey =
    Securedrop_protocol_minimal.Sign.impl_SigningKey__from_seed seed
  in
  let vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey =
    sk.Securedrop_protocol_minimal.Sign.f_vk
  in
  { f_sk = sk; f_vk = vk } <: t_FPFKeyPair
