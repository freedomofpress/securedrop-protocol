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

/// The public keys that make up one ephemeral key bundle
type t_KeyBundlePublic = {
  f_apke_pk:Securedrop_protocol_minimal.Message.t_MessagePublicKey;
  f_metadata_pk:Securedrop_protocol_minimal.Metadata.t_MetadataPublicKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core_models.Fmt.t_Debug t_KeyBundlePublic

unfold
let impl_5 = impl_5'

let impl_6: Core_models.Clone.t_Clone t_KeyBundlePublic =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Serialize the bundle public keys in canonical byte order for signing.
/// Layout: `pk_{J,i}^{APKE_E}(DHKEM) || pk_{J,i}^{APKE_E}(ML-KEM) || pk_{J,i}^{PKE_E}(X-Wing)`
let impl_KeyBundlePublic__as_bytes (self: t_KeyBundlePublic)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Collect.f_extend #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #u8
      #FStar.Tactics.Typeclasses.solve
      #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      out
      (Securedrop_protocol_minimal.Message.impl_MessagePublicKey__as_bytes self.f_apke_pk
        <:
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Collect.f_extend #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #u8
      #FStar.Tactics.Typeclasses.solve
      #(t_Slice u8)
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

type t_SignedMessageKeyBundle = {
  f_bundle:t_MessageKeyBundle;
  f_selfsig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey
}

type t_SignedLongtermPubKeyBytes =
  | SignedLongtermPubKeyBytes : t_Array u8 (mk_usize 1248) -> t_SignedLongtermPubKeyBytes

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Core_models.Fmt.t_Debug t_SignedLongtermPubKeyBytes

unfold
let impl_7 = impl_7'

let impl_8: Core_models.Clone.t_Clone t_SignedLongtermPubKeyBytes =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Serialize long-term public keys into the canonical byte encoding.
/// Byte layout (per spec §3.1): `pk_J^APKE || pk_J^fetch`
/// where `pk_J^APKE = pk_J^AKEM (DH-AKEM) || pk_J^PQ (ML-KEM)`
let impl_SignedLongtermPubKeyBytes__from_keys
      (reply_apke: Securedrop_protocol_minimal.Message.t_MessagePublicKey)
      (fetch_pk: Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
    : t_SignedLongtermPubKeyBytes =
  let apke_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Securedrop_protocol_minimal.Message.impl_MessagePublicKey__as_bytes reply_apke
  in
  let fetch_bytes:t_Array u8 (mk_usize 32) =
    Securedrop_protocol_minimal.Primitives.X25519.impl_DHPublicKey__into_bytes fetch_pk
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
          (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              apke_bytes
            <:
            t_Slice u8)
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
  SignedLongtermPubKeyBytes pubkey_bytes <: t_SignedLongtermPubKeyBytes

/// Return the canonical byte encoding of the long-term public keys.
let impl_SignedLongtermPubKeyBytes__as_bytes (self: t_SignedLongtermPubKeyBytes) : t_Slice u8 =
  self._0 <: t_Slice u8

type t_Enrollment = {
  f_bundle:t_SignedLongtermPubKeyBytes;
  f_selfsig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey;
  f_keys:(Securedrop_protocol_minimal.Sign.t_VerifyingKey &
    Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey &
    Securedrop_protocol_minimal.Message.t_MessagePublicKey)
}

let impl_9: Core_models.Clone.t_Clone t_Enrollment =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_10': Core_models.Fmt.t_Debug t_Enrollment

unfold
let impl_10 = impl_10'

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

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3: Core_models.Fmt.t_Debug t_FPFKeyPair =
  {
    f_fmt_pre = (fun (self: t_FPFKeyPair) (f: Core_models.Fmt.t_Formatter) -> true);
    f_fmt_post
    =
    (fun
        (self: t_FPFKeyPair)
        (f: Core_models.Fmt.t_Formatter)
        (out1:
          (Core_models.Fmt.t_Formatter &
            Core_models.Result.t_Result Prims.unit Core_models.Fmt.t_Error))
        ->
        true);
    f_fmt
    =
    fun (self: t_FPFKeyPair) (f: Core_models.Fmt.t_Formatter) ->
      let
      (tmp0: Core_models.Fmt.Builders.t_DebugStruct),
      (out: Core_models.Result.t_Result Prims.unit Core_models.Fmt.t_Error) =
        Core_models.Fmt.Builders.impl_3__finish_non_exhaustive (Rust_primitives.Hax.failure "At this position, Hax was expecting an expression of the shape `&mut _`.\nHax forbids `f(x)` (where `f` expects a mutable reference as input) when `x` is not a [1mplace expression[0m[90m[1][0m or when it is a dereference expression.\n\n[1]: https://doc.rust-lang.org/reference/expressions.html#place-expressions-and-value-expressions\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
              "deref(\n core_models::fmt::builders::impl_3__field::<\n lifetime!(something),\n lifetime!(something),\n >(\n &mut (core_models::fmt::impl_11__debug_struct::<\n lifetime!(something),\n >(&mut (f), &(deref(\"FP..."

            <:
            Core_models.Fmt.Builders.t_DebugStruct)
      in
      let _:Prims.unit =
        Rust_primitives.Hax.failure "Explicit rejection by a phase in the Hax engine:\na node of kind [Arbitrary_lhs] have been found in the AST\n\n[90mNote: the error was labeled with context `reject_ArbitraryLhs`.\n[0m"
          "(rust_primitives::hax::failure(\n \"At this position, Hax was expecting an expression of the shape `&mut _`.\nHax forbids `f(x)` (where `f` expects a mutable reference as input) when `x` is not a \027[1..."

      in
      let hax_temp_output:Core_models.Result.t_Result Prims.unit Core_models.Fmt.t_Error = out in
      f, hax_temp_output
      <:
      (Core_models.Fmt.t_Formatter & Core_models.Result.t_Result Prims.unit Core_models.Fmt.t_Error)
  }

/// Generate a new FPF key pair.
/// # Errors
/// Returns an error if the key generation fails.
let impl_FPFKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error =
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
    Core_models.Result.Result_Ok ({ f_sk = sk; f_vk = vk } <: t_FPFKeyPair)
    <:
    Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_FPFKeyPair Anyhow.t_Error

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
