module Securedrop_protocol.Client
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Trait for structured messages that can be serialized for encryption
class t_StructuredMessage (v_Self: Type0) = {
  f_into_bytes_pre:v_Self -> Type0;
  f_into_bytes_post:v_Self -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global -> Type0;
  f_into_bytes:x0: v_Self
    -> Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        (f_into_bytes_pre x0)
        (fun result -> f_into_bytes_post x0 result)
}

/// Internal trait for private key access - not to be exposed
class t_ClientPrivate (v_Self: Type0) = {
  f_fetching_private_key_pre:v_Self -> Type0;
  f_fetching_private_key_post:
      v_Self ->
      Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
    -> Type0;
  f_fetching_private_key:x0: v_Self
    -> Prims.Pure (Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
        (f_fetching_private_key_pre x0)
        (fun result -> f_fetching_private_key_post x0 result);
  f_message_enc_private_key_dhakem_pre:v_Self -> Type0;
  f_message_enc_private_key_dhakem_post:
      v_Self ->
      Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
    -> Type0;
  f_message_enc_private_key_dhakem:x0: v_Self
    -> Prims.Pure (Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error)
        (f_message_enc_private_key_dhakem_pre x0)
        (fun result -> f_message_enc_private_key_dhakem_post x0 result)
}

(* item error backend: Explicit rejection by a phase in the Hax engine:
a node of kind [Trait_item_default] have been found in the AST

[90mNote: the error was labeled with context `reject_TraitItemDefault`.
[0m
Last available AST for this item:

/** Common client functionality for source and journalist clients*/#[feature(register_tool)]#[register_tool(_hax)]trait t_Client<Self_>{type f_NewsroomKey: TodoPrintRustBoundsTyp;
#[_hax::json("\"TraitMethodNoPrePost\"")]fn f_newsroom_verifying_key_pre(_: Self) -> bool;
#[_hax::json("\"TraitMethodNoPrePost\"")]fn f_newsroom_verifying_key_post(_: Self,_: core_models::option::t_Option<proj_asso_type!()>) -> bool;
fn f_newsroom_verifying_key(_: Self) -> core_models::option::t_Option<proj_asso_type!()>;
#[_hax::json("\"TraitMethodNoPrePost\"")]fn f_set_newsroom_verifying_key_pre(_: Self,_: proj_asso_type!()) -> bool;
#[_hax::json("\"TraitMethodNoPrePost\"")]fn f_set_newsroom_verifying_key_post(_: Self,_: proj_asso_type!(),_: Self) -> bool;
fn f_set_newsroom_verifying_key(_: Self,_: proj_asso_type!()) -> Self;
fn f_get_newsroom_verifying_key((self: Self)) -> core_models::result::t_Result<proj_asso_type!(), anyhow::t_Error>{core_models::option::impl__ok_or_else::<proj_asso_type!(),anyhow::t_Error,arrow!(tuple0 -> anyhow::t_Error)>(securedrop_protocol::client::f_newsroom_verifying_key(self),(|_| {{let error: anyhow::t_Error = {anyhow::__private::format_err(core_models::fmt::rt::impl_1__new_const::<generic_value!(todo)>(["Newsroom verifying key not available"]))};anyhow::__private::must_use(error)}}))}
#[_hax::json("\"TraitMethodNoPrePost\"")]fn f_fetch_message_ids_pre<R>(_: Self,_: R) -> bool where _: rand_core::t_RngCore<R>,_: rand_core::t_CryptoRng<R>;
#[_hax::json("\"TraitMethodNoPrePost\"")]fn f_fetch_message_ids_post<R>(_: Self,_: R,_: tuple2<R, securedrop_protocol::messages::core::t_MessageChallengeFetchRequest>) -> bool where _: rand_core::t_RngCore<R>,_: rand_core::t_CryptoRng<R>;
fn f_fetch_message_ids<R>(_: Self,_: R) -> tuple2<R, securedrop_protocol::messages::core::t_MessageChallengeFetchRequest> where _: rand_core::t_RngCore<R>,_: rand_core::t_CryptoRng<R>;
fn f_process_message_id_response((self: Self,response: securedrop_protocol::messages::core::t_MessageChallengeFetchResponse)) -> core_models::result::t_Result<alloc::vec::t_Vec<uuid::t_Uuid, alloc::alloc::t_Global>, anyhow::t_Error> where _: securedrop_protocol::client::t_ClientPrivate<Self>{{let message_ids: alloc::vec::t_Vec<uuid::t_Uuid, alloc::alloc::t_Global> = {alloc::vec::impl__new::<uuid::t_Uuid>(Tuple0)};(match (securedrop_protocol::client::f_fetching_private_key(self)) {core_models::result::Result_Ok(fetching_private_key) => {(match (rust_primitives::hax::folds::fold_return(core_models::iter::traits::collect::f_into_iter(proj_securedrop_protocol::messages::core::f_messages(response)),message_ids,(|message_ids,Tuple2(q_i, cid_i)| {{let q_public_key: securedrop_protocol::primitives::x25519::t_DHPublicKey = {securedrop_protocol::primitives::x25519::dh_public_key_from_scalar(core_models::result::impl__unwrap_or::<[int;32],alloc::vec::t_Vec<int, alloc::alloc::t_Global>>(core_models::convert::f_try_into(core_models::clone::f_clone(q_i)),rust_primitives::hax::repeat(0,32)))};(match (securedrop_protocol::primitives::x25519::dh_shared_secret(q_public_key,fetching_private_key)) {core_models::result::Result_Ok(hoist1) => {{let k_i: [int;32] = {securedrop_protocol::primitives::x25519::impl_DHSharedSecret__into_bytes(hoist1)};(match (securedrop_protocol::primitives::decrypt_message_id(rust_primitives::unsize(k_i),core_models::ops::deref::f_deref(cid_i))) {core_models::result::Result_Ok(decrypted_id) => {(if rust_primitives::hax::machine_int::eq(alloc::vec::impl_1__len::<int,alloc::alloc::t_Global>(decrypted_id),16){(match (core_models::convert::f_try_into(decrypted_id)) {core_models::result::Result_Ok(id_bytes) => {{let uuid: uuid::t_Uuid = {uuid::builder::impl__from_bytes(id_bytes)};{let message_ids: alloc::vec::t_Vec<uuid::t_Uuid, alloc::alloc::t_Global> = {alloc::vec::impl_1__push::<uuid::t_Uuid,alloc::alloc::t_Global>(message_ids,uuid)};core_models::ops::control_flow::ControlFlow_Continue(message_ids)}}},_ => {core_models::ops::control_flow::ControlFlow_Continue(message_ids)}})} else {core_models::ops::control_flow::ControlFlow_Continue(message_ids)})},core_models::result::Result_Err(_) => {core_models::ops::control_flow::ControlFlow_Continue(message_ids)}})}},core_models::result::Result_Err(err) => {core_models::ops::control_flow::ControlFlow_Break(core_models::ops::control_flow::ControlFlow_Break(core_models::result::Result_Err(err)))}})}}))) {core_models::ops::control_flow::ControlFlow_Break(ret) => {ret},core_models::ops::control_flow::ControlFlow_Continue(message_ids) => {core_models::result::Result_Ok(message_ids)}})},core_models::result::Result_Err(err) => {core_models::result::Result_Err(err)}})}}
fn f_fetch_message((self: Self,_message_id: uuid::t_Uuid)) -> core_models::option::t_Option<securedrop_protocol::messages::core::t_MessageBundle>{rust_primitives::hax::never_to_any(core_models::panicking::panic_fmt(core_models::fmt::rt::impl_1__new_v1::<generic_value!(todo),generic_value!(todo)>(["not implemented: "],[])))}
fn f_submit_structured_message<M, R>((self: Self,message: M,recipient_message_keys: tuple2<securedrop_protocol::primitives::dh_akem::t_DhAkemPublicKey, securedrop_protocol::primitives::mlkem::t_MLKEM768PublicKey>,recipient_metadata_key: securedrop_protocol::primitives::xwing::t_XWingPublicKey,recipient_fetch_key: securedrop_protocol::primitives::x25519::t_DHPublicKey,sender_dh_private_key: securedrop_protocol::primitives::dh_akem::t_DhAkemPrivateKey,sender_dh_public_key: securedrop_protocol::primitives::dh_akem::t_DhAkemPublicKey,rng: R)) -> tuple2<R, core_models::result::t_Result<securedrop_protocol::messages::core::t_Message, anyhow::t_Error>> where _: securedrop_protocol::client::t_StructuredMessage<M>,_: rand_core::t_RngCore<R>,_: rand_core::t_CryptoRng<R>{{let padded_message: alloc::vec::t_Vec<int, alloc::alloc::t_Global> = {securedrop_protocol::primitives::pad::pad_message(core_models::ops::deref::f_deref(securedrop_protocol::client::f_into_bytes(message)))};{let Tuple2(tmp0, out): tuple2<R, core_models::result::t_Result<tuple2<tuple2<alloc::vec::t_Vec<int, alloc::alloc::t_Global>, alloc::vec::t_Vec<int, alloc::alloc::t_Global>>, alloc::vec::t_Vec<int, alloc::alloc::t_Global>>, anyhow::t_Error>> = {securedrop_protocol::primitives::auth_encrypt::<R>(rng,sender_dh_private_key,recipient_message_keys,core_models::ops::deref::f_deref(padded_message))};{let rng: R = {tmp0};(match (out) {core_models::result::Result_Ok(Tuple2(Tuple2(c1, c2), c_double_prime)) => {(match (securedrop_protocol::primitives::enc(recipient_metadata_key,sender_dh_public_key,core_models::ops::deref::f_deref(c1),core_models::ops::deref::f_deref(c2))) {core_models::result::Result_Ok(c_prime) => {{let ciphertext: alloc::vec::t_Vec<int, alloc::alloc::t_Global> = {alloc::slice::impl__concat::<alloc::vec::t_Vec<int, alloc::alloc::t_Global>,int>(rust_primitives::unsize([c_prime,c_double_prime]))};{let Tuple2(tmp0, out): tuple2<R, core_models::result::t_Result<[int;32], anyhow::t_Error>> = {securedrop_protocol::primitives::x25519::generate_random_scalar::<R>(rng)};{let rng: R = {tmp0};(match (core_models::result::impl__map_err::<[int;32],anyhow::t_Error,anyhow::t_Error,arrow!(anyhow::t_Error -> anyhow::t_Error)>(out,(|e| {{let args: tuple1<anyhow::t_Error> = {Tuple1(e)};{let args: [core_models::fmt::rt::t_Argument;1] = {[core_models::fmt::rt::impl__new_display::<anyhow::t_Error>(proj_proj_tuple0(args))]};anyhow::error::impl__msg::<alloc::string::t_String>(core_models::hint::must_use::<alloc::string::t_String>(alloc::fmt::format(core_models::fmt::rt::impl_1__new_v1::<generic_value!(todo),generic_value!(todo)>(["Failed to generate random scalar: "],args))))}}}))) {core_models::result::Result_Ok(x_bytes) => {{let x_share: securedrop_protocol::primitives::x25519::t_DHPublicKey = {securedrop_protocol::primitives::x25519::dh_public_key_from_scalar(x_bytes)};(match (securedrop_protocol::primitives::x25519::dh_shared_secret(recipient_fetch_key,x_bytes)) {core_models::result::Result_Ok(z_share) => {{let request: securedrop_protocol::messages::core::t_Message = {securedrop_protocol::messages::core::Message{f_ciphertext:ciphertext,f_dh_share_z:alloc::slice::impl__to_vec::<int>(rust_primitives::unsize(securedrop_protocol::primitives::x25519::impl_DHSharedSecret__into_bytes(z_share))),f_dh_share_x:alloc::slice::impl__to_vec::<int>(rust_primitives::unsize(securedrop_protocol::primitives::x25519::impl_DHPublicKey__into_bytes(x_share))),}};{let hax_temp_output: core_models::result::t_Result<securedrop_protocol::messages::core::t_Message, anyhow::t_Error> = {core_models::result::Result_Ok(request)};Tuple2(rng,hax_temp_output)}}},core_models::result::Result_Err(err) => {Tuple2(rng,core_models::result::Result_Err(err))}})}},core_models::result::Result_Err(err) => {Tuple2(rng,core_models::result::Result_Err(err))}})}}}},core_models::result::Result_Err(err) => {Tuple2(rng,core_models::result::Result_Err(err))}})},core_models::result::Result_Err(err) => {Tuple2(rng,core_models::result::Result_Err(err))}})}}}}}

Last AST:
/** print_rust: pitem: not implemented  (item: { Concrete_ident.T.def_id =
  { Explicit_def_id.T.is_constructor = false;
    def_id =
    { Types.index = (0, 0, None); is_local = true; kind = Types.Trait;
      krate = "securedrop_protocol";
      parent =
      (Some { Types.contents =
              { Types.id = 0;
                value =
                { Types.index = (0, 0, None); is_local = true;
                  kind = Types.Mod; krate = "securedrop_protocol";
                  parent =
                  (Some { Types.contents =
                          { Types.id = 0;
                            value =
                            { Types.index = (0, 0, None); is_local = true;
                              kind = Types.Mod;
                              krate = "securedrop_protocol"; parent = None;
                              path = [] }
                            }
                          });
                  path =
                  [{ Types.data = (Types.TypeNs "client"); disambiguator = 0
                     }
                    ]
                  }
                }
              });
      path =
      [{ Types.data = (Types.TypeNs "client"); disambiguator = 0 };
        { Types.data = (Types.TypeNs "Client"); disambiguator = 0 }]
      }
    };
  moved = None; suffix = None }) */
const _: () = ();
 *)
