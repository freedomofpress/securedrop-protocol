module Securedrop_protocol_minimal.Sign
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  ()

let v_KEY_LEN_ED25519: usize = mk_usize 32

class t_DomainTag (v_Self: Type0) = {
  f_tag_pre:Prims.unit -> Type0;
  f_tag_post:Prims.unit -> t_Slice u8 -> Type0;
  f_tag:x0: Prims.unit
    -> Prims.Pure (t_Slice u8) (f_tag_pre x0) (fun result -> f_tag_post x0 result)
}

/// Journalist self-signature over long-term public keys (step 3.1).
type t_JournalistLongTermKey = | JournalistLongTermKey : t_JournalistLongTermKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_12': Core_models.Fmt.t_Debug t_JournalistLongTermKey

unfold
let impl_12 = impl_12'

let impl_13: Core_models.Clone.t_Clone t_JournalistLongTermKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_14': Core_models.Marker.t_Copy t_JournalistLongTermKey

unfold
let impl_14 = impl_14'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_15': Core_models.Marker.t_StructuralPartialEq t_JournalistLongTermKey

unfold
let impl_15 = impl_15'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_16': Core_models.Cmp.t_PartialEq t_JournalistLongTermKey t_JournalistLongTermKey

unfold
let impl_16 = impl_16'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_17': Core_models.Cmp.t_Eq t_JournalistLongTermKey

unfold
let impl_17 = impl_17'

/// Journalist self-signature over ephemeral key bundles (step 3.2).
type t_JournalistEphemeralKey = | JournalistEphemeralKey : t_JournalistEphemeralKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_18': Core_models.Fmt.t_Debug t_JournalistEphemeralKey

unfold
let impl_18 = impl_18'

let impl_19: Core_models.Clone.t_Clone t_JournalistEphemeralKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_20': Core_models.Marker.t_Copy t_JournalistEphemeralKey

unfold
let impl_20 = impl_20'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_21': Core_models.Marker.t_StructuralPartialEq t_JournalistEphemeralKey

unfold
let impl_21 = impl_21'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_22': Core_models.Cmp.t_PartialEq t_JournalistEphemeralKey t_JournalistEphemeralKey

unfold
let impl_22 = impl_22'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_23': Core_models.Cmp.t_Eq t_JournalistEphemeralKey

unfold
let impl_23 = impl_23'

/// Newsroom signature over a journalist's verifying key (steps 3.1, 5).
type t_NewsroomOnJournalist = | NewsroomOnJournalist : t_NewsroomOnJournalist

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_24': Core_models.Fmt.t_Debug t_NewsroomOnJournalist

unfold
let impl_24 = impl_24'

let impl_25: Core_models.Clone.t_Clone t_NewsroomOnJournalist =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_26': Core_models.Marker.t_Copy t_NewsroomOnJournalist

unfold
let impl_26 = impl_26'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_27': Core_models.Marker.t_StructuralPartialEq t_NewsroomOnJournalist

unfold
let impl_27 = impl_27'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_28': Core_models.Cmp.t_PartialEq t_NewsroomOnJournalist t_NewsroomOnJournalist

unfold
let impl_28 = impl_28'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_29': Core_models.Cmp.t_Eq t_NewsroomOnJournalist

unfold
let impl_29 = impl_29'

/// FPF signature over the newsroom's verifying key (step 2).
type t_FpfOnNewsroom = | FpfOnNewsroom : t_FpfOnNewsroom

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_30': Core_models.Fmt.t_Debug t_FpfOnNewsroom

unfold
let impl_30 = impl_30'

let impl_31: Core_models.Clone.t_Clone t_FpfOnNewsroom =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_32': Core_models.Marker.t_Copy t_FpfOnNewsroom

unfold
let impl_32 = impl_32'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_33': Core_models.Marker.t_StructuralPartialEq t_FpfOnNewsroom

unfold
let impl_33 = impl_33'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_34': Core_models.Cmp.t_PartialEq t_FpfOnNewsroom t_FpfOnNewsroom

unfold
let impl_34 = impl_34'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_35': Core_models.Cmp.t_Eq t_FpfOnNewsroom

unfold
let impl_35 = impl_35'

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl: t_DomainTag t_JournalistLongTermKey =
  {
    f_tag_pre = (fun (_: Prims.unit) -> true);
    f_tag_post = (fun (_: Prims.unit) (out: t_Slice u8) -> true);
    f_tag
    =
    fun (_: Prims.unit) ->
      (let list =
          [
            mk_u8 106;
            mk_u8 45;
            mk_u8 115;
            mk_u8 105;
            mk_u8 103;
            mk_u8 45;
            mk_u8 108;
            mk_u8 116;
            mk_u8 107
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 9);
        Rust_primitives.Hax.array_of_list 9 list)
      <:
      t_Slice u8
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_DomainTag_for_JournalistEphemeralKey: t_DomainTag t_JournalistEphemeralKey =
  {
    f_tag_pre = (fun (_: Prims.unit) -> true);
    f_tag_post = (fun (_: Prims.unit) (out: t_Slice u8) -> true);
    f_tag
    =
    fun (_: Prims.unit) ->
      (let list =
          [
            mk_u8 106;
            mk_u8 45;
            mk_u8 115;
            mk_u8 105;
            mk_u8 103;
            mk_u8 45;
            mk_u8 101;
            mk_u8 112;
            mk_u8 104
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 9);
        Rust_primitives.Hax.array_of_list 9 list)
      <:
      t_Slice u8
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_DomainTag_for_NewsroomOnJournalist: t_DomainTag t_NewsroomOnJournalist =
  {
    f_tag_pre = (fun (_: Prims.unit) -> true);
    f_tag_post = (fun (_: Prims.unit) (out: t_Slice u8) -> true);
    f_tag
    =
    fun (_: Prims.unit) ->
      (let list = [mk_u8 110; mk_u8 114; mk_u8 45; mk_u8 115; mk_u8 105; mk_u8 103] in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 6);
        Rust_primitives.Hax.array_of_list 6 list)
      <:
      t_Slice u8
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_DomainTag_for_FpfOnNewsroom: t_DomainTag t_FpfOnNewsroom =
  {
    f_tag_pre = (fun (_: Prims.unit) -> true);
    f_tag_post = (fun (_: Prims.unit) (out: t_Slice u8) -> true);
    f_tag
    =
    fun (_: Prims.unit) ->
      (let list =
          [
            mk_u8 102; mk_u8 112; mk_u8 102; mk_u8 45; mk_u8 115; mk_u8 105; mk_u8 103; mk_u8 45;
            mk_u8 110; mk_u8 114
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 10);
        Rust_primitives.Hax.array_of_list 10 list)
      <:
      t_Slice u8
  }

/// An Ed25519 signature carrying its domain at the type level.
/// A `Signature<D>` can only be verified against a message using the same
/// domain `D`, making cross-domain misuse a compile error rather than a
/// runtime failure.
type t_Signature (v_D: Type0) {| i0: t_DomainTag v_D |} = {
  f_bytes:t_Array u8 (mk_usize 64);
  f_e_phantom:Core_models.Marker.t_PhantomData v_D
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_5 (#v_D: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DomainTag v_D)
    : Core_models.Clone.t_Clone (t_Signature v_D) =
  {
    f_clone_pre = (fun (self: t_Signature v_D) -> true);
    f_clone_post = (fun (self: t_Signature v_D) (out: t_Signature v_D) -> true);
    f_clone = fun (self: t_Signature v_D) -> self
  }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_4 (#v_D: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DomainTag v_D)
    : Core_models.Marker.t_Copy (t_Signature v_D) = { _super_i0 = FStar.Tactics.Typeclasses.solve }

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_6 (#v_D: Type0) (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DomainTag v_D)
    : Core_models.Cmp.t_PartialEq (t_Signature v_D) (t_Signature v_D) =
  {
    f_eq_pre = (fun (self: t_Signature v_D) (other: t_Signature v_D) -> true);
    f_eq_post = (fun (self: t_Signature v_D) (other: t_Signature v_D) (out: bool) -> true);
    f_eq = fun (self: t_Signature v_D) (other: t_Signature v_D) -> self.f_bytes =. other.f_bytes
  }

/// Reconstruct a [`Signature`] from its serialization.
let impl_7__from_bytes
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DomainTag v_D)
      (bytes: t_Array u8 (mk_usize 64))
    : t_Signature v_D =
  {
    f_bytes = bytes;
    f_e_phantom = Core_models.Marker.PhantomData <: Core_models.Marker.t_PhantomData v_D
  }
  <:
  t_Signature v_D

/// The byte serialization of this signature.
let impl_7__as_bytes
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DomainTag v_D)
      (self: t_Signature v_D)
    : t_Array u8 (mk_usize 64) = self.f_bytes

#push-options "--admit_smt_queries true"

/// Construct the tagged signing preimage: `len(tag) || tag || msg`.
let tagged_preimage
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DomainTag v_D)
      (msg: t_Slice u8)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let tag:t_Slice u8 = f_tag #v_D #FStar.Tactics.Typeclasses.solve () in
  let preimage:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #u8
      ((mk_usize 1 +! (Core_models.Slice.impl__len #u8 tag <: usize) <: usize) +!
        (Core_models.Slice.impl__len #u8 msg <: usize)
        <:
        usize)
  in
  let preimage:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_1__push #u8
      #Alloc.Alloc.t_Global
      preimage
      (cast (Core_models.Slice.impl__len #u8 tag <: usize) <: u8)
  in
  let preimage:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global preimage tag
  in
  let preimage:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global preimage msg
  in
  preimage

#pop-options

/// An Ed25519 verification key.
type t_VerifyingKey = | VerifyingKey : t_Array u8 (mk_usize 32) -> t_VerifyingKey

let impl_40: Core_models.Clone.t_Clone t_VerifyingKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_39': Core_models.Marker.t_Copy t_VerifyingKey

unfold
let impl_39 = impl_39'

/// An Ed25519 signing key.
type t_SigningSecretKey = | SigningSecretKey : t_Array u8 (mk_usize 32) -> t_SigningSecretKey

let impl_VerifyingKey__as_bytes (self: t_VerifyingKey) : t_Array u8 (mk_usize 32) = self._0

let impl_VerifyingKey__from_bytes (bytes: t_Array u8 (mk_usize 32)) : t_VerifyingKey =
  VerifyingKey bytes <: t_VerifyingKey

let impl_SigningSecretKey__as_bytes (self: t_SigningSecretKey) : t_Array u8 (mk_usize 32) = self._0

let impl_SigningSecretKey__from_bytes (bytes: t_Array u8 (mk_usize 32)) : t_SigningSecretKey =
  SigningSecretKey bytes <: t_SigningSecretKey

type t_SigningKey = {
  f_vk:t_VerifyingKey;
  f_sk:t_SigningSecretKey
}

/// Generate a signing key from the supplied `rng`.
let impl_SigningKey__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (v_R & Core_models.Result.t_Result t_SigningKey Anyhow.t_Error) =
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result (t_Array u8 (mk_usize 32) & t_Array u8 (mk_usize 32)) Anyhow.t_Error
  ) =
    Securedrop_protocol_minimal.Primitives.Provider.Ed25519.keygen #v_R rng
  in
  let rng:v_R = tmp0 in
  match
    out
    <:
    Core_models.Result.t_Result (t_Array u8 (mk_usize 32) & t_Array u8 (mk_usize 32)) Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok (sk, vk) ->
    let hax_temp_output:Core_models.Result.t_Result t_SigningKey Anyhow.t_Error =
      Core_models.Result.Result_Ok
      ({
          f_vk = VerifyingKey vk <: t_VerifyingKey;
          f_sk = SigningSecretKey sk <: t_SigningSecretKey
        }
        <:
        t_SigningKey)
      <:
      Core_models.Result.t_Result t_SigningKey Anyhow.t_Error
    in
    rng, hax_temp_output <: (v_R & Core_models.Result.t_Result t_SigningKey Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err <: Core_models.Result.t_Result t_SigningKey Anyhow.t_Error)
    <:
    (v_R & Core_models.Result.t_Result t_SigningKey Anyhow.t_Error)

/// Sign `msg` in domain `D`, returning a `Signature<D>`.
/// The actual preimage is `len(tag) || tag || msg` where `tag = D::TAG`.
let impl_SigningKey__sign
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DomainTag v_D)
      (self: t_SigningKey)
      (msg: t_Slice u8)
    : t_Signature v_D =
  let preimage:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = tagged_preimage #v_D msg in
  let bytes:t_Array u8 (mk_usize 64) =
    Securedrop_protocol_minimal.Primitives.Provider.Ed25519.sign (Alloc.Vec.impl_1__as_slice preimage

        <:
        t_Slice u8)
      (impl_SigningSecretKey__as_bytes self.f_sk <: t_Array u8 (mk_usize 32))
  in
  impl_7__from_bytes #v_D bytes

let impl_SigningKey__as_bytes (self: t_SigningKey) : t_Array u8 (mk_usize 32) =
  impl_SigningSecretKey__as_bytes self.f_sk

let impl_SigningKey__from_seed (seed: t_Array u8 (mk_usize 32)) : t_SigningKey =
  let pk:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let pk:t_Array u8 (mk_usize 32) =
    Securedrop_protocol_minimal.Primitives.Provider.Ed25519.secret_to_public pk seed
  in
  { f_vk = VerifyingKey pk <: t_VerifyingKey; f_sk = SigningSecretKey seed <: t_SigningSecretKey }
  <:
  t_SigningKey

/// Get the raw bytes of this verification key.
let impl_VerifyingKey__into_bytes (self: t_VerifyingKey) : t_Array u8 (mk_usize 32) = self._0

/// Verify `sig` over `msg`. The domain is determined by the type of `sig`.
/// Returns an error if the signature is invalid.
let impl_VerifyingKey__verify
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DomainTag v_D)
      (self: t_VerifyingKey)
      (msg: t_Slice u8)
      (sig: t_Signature v_D)
    : Core_models.Result.t_Result Prims.unit Anyhow.t_Error =
  let preimage:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = tagged_preimage #v_D msg in
  Core_models.Result.impl__map_err #Prims.unit
    #Anyhow.t_Error
    #Anyhow.t_Error
    #(Anyhow.t_Error -> Anyhow.t_Error)
    (Securedrop_protocol_minimal.Primitives.Provider.Ed25519.verify (Alloc.Vec.impl_1__as_slice preimage

          <:
          t_Slice u8)
        (impl_VerifyingKey__as_bytes self <: t_Array u8 (mk_usize 32))
        sig.f_bytes
      <:
      Core_models.Result.t_Result Prims.unit Anyhow.t_Error)
    (fun temp_0_ ->
        let _:Anyhow.t_Error = temp_0_ in
        let error:Anyhow.t_Error =
          Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                (let list = ["Signature verification failed"] in
                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                  Rust_primitives.Hax.array_of_list 1 list)
              <:
              Core_models.Fmt.t_Arguments)
        in
        Anyhow.__private.must_use error)
