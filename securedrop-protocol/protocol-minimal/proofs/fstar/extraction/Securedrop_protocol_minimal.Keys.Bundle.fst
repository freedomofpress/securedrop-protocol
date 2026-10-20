module Securedrop_protocol_minimal.Keys.Bundle
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Securedrop_protocol_minimal.Schemes.Message in
  let open Securedrop_protocol_minimal.Schemes.Metadata in
  ()

/// The public keys that make up one ephemeral key bundle
type t_KeyBundlePublic = {
  f_apke_pk:Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey;
  f_metadata_pk:Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataPublicKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Core_models.Fmt.t_Debug t_KeyBundlePublic

unfold
let impl_3 = impl_3'

let impl_4: Core_models.Clone.t_Clone t_KeyBundlePublic =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Serialize the bundle public keys in canonical byte order for signing.
/// Layout: `pk_{J,i}^{APKE_E}(DHKEM) || pk_{J,i}^{APKE_E}(ML-KEM) || pk_{J,i}^{PKE_E}(X-Wing)`
let impl_KeyBundlePublic__as_bytes (self: t_KeyBundlePublic)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let out:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      out
      (Alloc.Vec.impl_1__as_slice (Securedrop_protocol_minimal.Schemes.Message.impl_MessagePublicKey__as_bytes
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
      (Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataPublicKey__as_bytes self
            .f_metadata_pk
        <:
        t_Slice u8)
  in
  out

type t_MessageKeyBundle = {
  f_apke:Securedrop_protocol_minimal.Schemes.Message.t_MessageKeyPair;
  f_metadata_kp:Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataKeyPair
}

let impl_MessageKeyBundle__new
      (apke: Securedrop_protocol_minimal.Schemes.Message.t_MessageKeyPair)
      (metadata_kp: Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataKeyPair)
    : t_MessageKeyBundle = { f_apke = apke; f_metadata_kp = metadata_kp } <: t_MessageKeyBundle

let impl_MessageKeyBundle__public (self: t_MessageKeyBundle) : t_KeyBundlePublic =
  {
    f_apke_pk
    =
    Core_models.Clone.f_clone #Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey
      #FStar.Tactics.Typeclasses.solve
      (Securedrop_protocol_minimal.Schemes.Message.impl_MessageKeyPair__public_key self.f_apke
        <:
        Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey);
    f_metadata_pk
    =
    Core_models.Clone.f_clone #Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataPublicKey
      #FStar.Tactics.Typeclasses.solve
      (Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataKeyPair__public_key self
            .f_metadata_kp
        <:
        Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataPublicKey)
  }
  <:
  t_KeyBundlePublic

type t_SignedMessageKeyBundle = {
  f_bundle:t_MessageKeyBundle;
  f_selfsig:Securedrop_protocol_minimal.Schemes.Sign.t_Signature
  Securedrop_protocol_minimal.Schemes.Sign.t_JournalistEphemeralKey
}

type t_LongtermKeyBundle = {
  f_apke:Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey;
  f_fetch_pk:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core_models.Fmt.t_Debug t_LongtermKeyBundle

unfold
let impl_5 = impl_5'

let impl_6: Core_models.Clone.t_Clone t_LongtermKeyBundle =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_LongtermKeyBundle__LEN: usize =
  Securedrop_protocol_minimal.Schemes.Message.impl_MessagePublicKey__LEN +!
  Securedrop_protocol_minimal.Primitives.Ristretto255.impl_DHPublicKey__LEN

let impl_LongtermKeyBundle__new
      (apke: Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey)
      (fetch_pk: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey)
    : t_LongtermKeyBundle = { f_apke = apke; f_fetch_pk = fetch_pk } <: t_LongtermKeyBundle

/// Serialize long-term public keys into the canonical byte encoding.
/// Byte layout (per spec §3.1): `pk_J^APKE || pk_J^fetch`
/// where `pk_J^APKE = pk_J^AKEM (DH-AKEM) || pk_J^PQ (ML-KEM)`
let impl_LongtermKeyBundle__as_bytes (self: t_LongtermKeyBundle) : t_Array u8 (mk_usize 1248) =
  let apke_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Securedrop_protocol_minimal.Schemes.Message.impl_MessagePublicKey__as_bytes self.f_apke
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
