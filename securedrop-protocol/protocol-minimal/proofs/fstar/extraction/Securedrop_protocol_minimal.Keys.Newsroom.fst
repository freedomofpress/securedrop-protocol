module Securedrop_protocol_minimal.Keys.Newsroom
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  let open Securedrop_protocol_minimal.Sign in
  ()

/// Newsroom keypair used for signing.
type t_NewsroomKeyPair = {
  f_vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_sk:Securedrop_protocol_minimal.Sign.t_SigningKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl: Core_models.Fmt.t_Debug t_NewsroomKeyPair =
  {
    f_fmt_pre = (fun (self: t_NewsroomKeyPair) (f: Core_models.Fmt.t_Formatter) -> true);
    f_fmt_post
    =
    (fun
        (self: t_NewsroomKeyPair)
        (f: Core_models.Fmt.t_Formatter)
        (out1:
          (Core_models.Fmt.t_Formatter &
            Core_models.Result.t_Result Prims.unit Core_models.Fmt.t_Error))
        ->
        true);
    f_fmt
    =
    fun (self: t_NewsroomKeyPair) (f: Core_models.Fmt.t_Formatter) ->
      let
      (tmp0: Core_models.Fmt.Builders.t_DebugStruct),
      (out: Core_models.Result.t_Result Prims.unit Core_models.Fmt.t_Error) =
        Core_models.Fmt.Builders.impl_3__finish_non_exhaustive (Rust_primitives.Hax.failure "At this position, Hax was expecting an expression of the shape `&mut _`.\nHax forbids `f(x)` (where `f` expects a mutable reference as input) when `x` is not a [1mplace expression[0m[90m[1][0m or when it is a dereference expression.\n\n[1]: https://doc.rust-lang.org/reference/expressions.html#place-expressions-and-value-expressions\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
              "deref(\n core_models::fmt::builders::impl_3__field::<\n lifetime!(something),\n lifetime!(something),\n >(\n &mut (core_models::fmt::impl_11__debug_struct::<\n lifetime!(something),\n >(&mut (f), &(deref(\"Ne..."

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

let impl_NewsroomKeyPair__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : Core_models.Result.t_Result t_NewsroomKeyPair Anyhow.t_Error =
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
    Core_models.Result.Result_Ok ({ f_sk = sk; f_vk = vk } <: t_NewsroomKeyPair)
    <:
    Core_models.Result.t_Result t_NewsroomKeyPair Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result t_NewsroomKeyPair Anyhow.t_Error

/// Returns the verification key.
let impl_NewsroomKeyPair__verifying_key (self: t_NewsroomKeyPair)
    : Securedrop_protocol_minimal.Sign.t_VerifyingKey = self.f_vk

/// Sign `msg` in domain `D` using the newsroom signing key.
let impl_NewsroomKeyPair__sign
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i0:
          Securedrop_protocol_minimal.Sign.t_DomainTag v_D)
      (self: t_NewsroomKeyPair)
      (msg: t_Slice u8)
    : Securedrop_protocol_minimal.Sign.t_Signature v_D =
  Securedrop_protocol_minimal.Sign.impl_SigningKey__sign #v_D self.f_sk msg
