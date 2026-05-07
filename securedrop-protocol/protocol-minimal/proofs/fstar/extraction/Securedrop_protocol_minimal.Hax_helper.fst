module Securedrop_protocol_minimal.Hax_helper
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Kind in
  ()

/// do_something().map_err(|_| anyhow!("error_msg")) breaks hax.
class t_HaxHelper (v_Self: Type0) (v_T: Type0) (v_E: Type0) = {
  f_ok_or_err_pre:v_Self -> string -> Type0;
  f_ok_or_err_post:v_Self -> string -> Core_models.Result.t_Result v_T Anyhow.t_Error -> Type0;
  f_ok_or_err:x0: v_Self -> x1: string
    -> Prims.Pure (Core_models.Result.t_Result v_T Anyhow.t_Error)
        (f_ok_or_err_pre x0 x1)
        (fun result -> f_ok_or_err_post x0 x1 result);
  f_err_pre:v_Self -> string -> Type0;
  f_err_post:v_Self -> string -> Anyhow.t_Error -> Type0;
  f_err:x0: v_Self -> x1: string
    -> Prims.Pure Anyhow.t_Error (f_err_pre x0 x1) (fun result -> f_err_post x0 x1 result)
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl (#v_T #v_E: Type0) : t_HaxHelper (Core_models.Result.t_Result v_T v_E) v_T v_E =
  {
    f_ok_or_err_pre = (fun (self: Core_models.Result.t_Result v_T v_E) (msg: string) -> true);
    f_ok_or_err_post
    =
    (fun
        (self: Core_models.Result.t_Result v_T v_E)
        (msg: string)
        (out: Core_models.Result.t_Result v_T Anyhow.t_Error)
        ->
        true);
    f_ok_or_err
    =
    (fun (self: Core_models.Result.t_Result v_T v_E) (msg: string) ->
        match self <: Core_models.Result.t_Result v_T v_E with
        | Core_models.Result.Result_Ok v ->
          Core_models.Result.Result_Ok v <: Core_models.Result.t_Result v_T Anyhow.t_Error
        | Core_models.Result.Result_Err _ ->
          let error:Anyhow.t_Error =
            match msg <: string with
            | error ->
              Anyhow.Kind.impl_Adhoc__new #string
                (Anyhow.Kind.f_anyhow_kind #string #FStar.Tactics.Typeclasses.solve error
                  <:
                  Anyhow.Kind.t_Adhoc)
                error
          in
          Core_models.Result.Result_Err (Anyhow.__private.must_use error)
          <:
          Core_models.Result.t_Result v_T Anyhow.t_Error);
    f_err_pre = (fun (self: Core_models.Result.t_Result v_T v_E) (msg: string) -> true);
    f_err_post
    =
    (fun (self: Core_models.Result.t_Result v_T v_E) (msg: string) (out: Anyhow.t_Error) -> true);
    f_err
    =
    fun (self: Core_models.Result.t_Result v_T v_E) (msg: string) ->
      let error:Anyhow.t_Error =
        match msg <: string with
        | error ->
          Anyhow.Kind.impl_Adhoc__new #string
            (Anyhow.Kind.f_anyhow_kind #string #FStar.Tactics.Typeclasses.solve error
              <:
              Anyhow.Kind.t_Adhoc)
            error
      in
      Anyhow.__private.must_use error
  }
