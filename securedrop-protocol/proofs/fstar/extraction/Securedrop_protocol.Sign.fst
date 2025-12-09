module Securedrop_protocol.Sign
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_ed25519.Impl_hacl in
  ()

/// An Ed25519 verification key.
type t_VerifyingKey = | VerifyingKey : Libcrux_ed25519.Impl_hacl.t_VerificationKey -> t_VerifyingKey

/// An Ed25519 signing key.
type t_SigningKey = {
  f_vk:t_VerifyingKey;
  f_sk:Libcrux_ed25519.Impl_hacl.t_SigningKey
}

let impl_4: Core_models.Clone.t_Clone t_VerifyingKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Core_models.Marker.t_Copy t_VerifyingKey

unfold
let impl_3 = impl_3'

/// An Ed25519 signature.
type t_Signature = | Signature : t_Array u8 (mk_usize 64) -> t_Signature

type t_SelfSignature = | SelfSignature : t_Signature -> t_SelfSignature

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core_models.Fmt.t_Debug t_SelfSignature

unfold
let impl_5 = impl_5'

let impl_6: Core_models.Clone.t_Clone t_SelfSignature =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_SelfSignature__as_signature (self: t_SelfSignature) : t_Signature = self._0

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Core_models.Fmt.t_Debug t_Signature

unfold
let impl_7 = impl_7'

let impl_8: Core_models.Clone.t_Clone t_Signature =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

(* item error backend: The support in hax of function with one or more inputs of type `&mut _` is limited.
Only trivial patterns are allowed there: `fn f(x: &mut (T, U)) ...` is allowed while `f((x, y): &mut (T, U))` is rejected.

This is discussed in issue https://github.com/hacspec/hax/issues/1405.
Please upvote or comment this issue if you see this error message.
[90mNote: the error was labeled with context `AndMutDefsite`.
[0m
Last available AST for this item:

/// Generate a signing key from the supplied `rng`.
#[feature(register_tool)]
#[register_tool(_hax)]
fn impl_SigningKey__new<Anonymous: 'unk, impl_CryptoRng>(
    mut rng: &mut impl_CryptoRng,
) -> core_models::result::t_Result<
    securedrop_protocol::sign::t_SigningKey,
    anyhow::t_Error,
>
where
    _: rand_core::t_CryptoRng<impl_CryptoRng>,
{
    {
        let Tuple2(
            sk,
            vk,
        ): tuple2<
            libcrux_ed25519::impl_hacl::t_SigningKey,
            libcrux_ed25519::impl_hacl::t_VerificationKey,
        > = {
            (match (core_models::result::impl__map_err::<
                tuple2<
                    libcrux_ed25519::impl_hacl::t_SigningKey,
                    libcrux_ed25519::impl_hacl::t_VerificationKey,
                >,
                libcrux_ed25519::impl_hacl::t_Error,
                anyhow::t_Error,
                arrow!(libcrux_ed25519::impl_hacl::t_Error -> anyhow::t_Error),
            >(
                libcrux_ed25519::impl_hacl::generate_key_pair::<
                    &mut impl_CryptoRng,
                >(&mut (deref(&mut (rng)))),
                (|_| {
                    anyhow::__private::must_use({
                        let error: anyhow::t_Error = {
                            anyhow::__private::format_err(
                                core_models::fmt::rt::impl_1__new_const::<
                                    lifetime!(something),
                                    generic_value!(todo),
                                >(&(deref(&(["Key generation failed"])))),
                            )
                        };
                        { error }
                    })
                }),
            )) {
                core_models::result::Result_Ok(ok) => ok,
                core_models::result::Result_Err(err) => {
                    (return core_models::result::Result_Err(err))
                }
            })
        };
        {
            core_models::result::Result_Ok(securedrop_protocol::sign::SigningKey {
                f_vk: securedrop_protocol::sign::VerifyingKey(vk),
                f_sk: sk,
            })
        }
    }
}


Last AST:
/** print_rust: pitem: not implemented  (item: { Concrete_ident.T.def_id =
  { Explicit_def_id.T.is_constructor = false;
    def_id =
    { Types.index = (0, 0, None); is_local = true; kind = Types.AssocFn;
      krate = "securedrop_protocol";
      parent =
      (Some { Types.contents =
              { Types.id = 0;
                value =
                { Types.index = (0, 0, None); is_local = true;
                  kind = Types.Impl {of_trait = false};
                  krate = "securedrop_protocol";
                  parent =
                  (Some { Types.contents =
                          { Types.id = 0;
                            value =
                            { Types.index = (0, 0, None); is_local = true;
                              kind = Types.Mod;
                              krate = "securedrop_protocol";
                              parent =
                              (Some { Types.contents =
                                      { Types.id = 0;
                                        value =
                                        { Types.index = (0, 0, None);
                                          is_local = true; kind = Types.Mod;
                                          krate = "securedrop_protocol";
                                          parent = None; path = [] }
                                        }
                                      });
                              path =
                              [{ Types.data = (Types.TypeNs "sign");
                                 disambiguator = 0 }
                                ]
                              }
                            }
                          });
                  path =
                  [{ Types.data = (Types.TypeNs "sign"); disambiguator = 0 };
                    { Types.data = Types.Impl; disambiguator = 1 }]
                  }
                }
              });
      path =
      [{ Types.data = (Types.TypeNs "sign"); disambiguator = 0 };
        { Types.data = Types.Impl; disambiguator = 1 };
        { Types.data = (Types.ValueNs "new"); disambiguator = 0 }]
      }
    };
  moved = None; suffix = None }) */
const _: () = ();
 *)

/// Create a signature on `msg` using this `SigningKey`.
let impl_SigningKey__sign (self: t_SigningKey) (msg: t_Slice u8) : t_Signature =
  let signature_bytes:t_Array u8 (mk_usize 64) =
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 64))
      #Libcrux_ed25519.Impl_hacl.t_Error
      (Libcrux_ed25519.Impl_hacl.sign msg
          (Core_models.Convert.f_as_ref #Libcrux_ed25519.Impl_hacl.t_SigningKey
              #(t_Array u8 (mk_usize 32))
              #FStar.Tactics.Typeclasses.solve
              self.f_sk
            <:
            t_Array u8 (mk_usize 32))
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 64)) Libcrux_ed25519.Impl_hacl.t_Error)
      "Signing should not fail with valid key"
  in
  Signature signature_bytes <: t_Signature

/// Get the raw bytes of this verification key
let impl_VerifyingKey__into_bytes (self: t_VerifyingKey) : t_Array u8 (mk_usize 32) =
  Libcrux_ed25519.Impl_hacl.impl_VerificationKey__into_bytes self._0

/// Verify a signature on `msg` using this `VerifyingKey`
let impl_VerifyingKey__verify (self: t_VerifyingKey) (msg: t_Slice u8) (signature: t_Signature)
    : Core_models.Result.t_Result Prims.unit Anyhow.t_Error =
  Core_models.Result.impl__map_err #Prims.unit
    #Libcrux_ed25519.Impl_hacl.t_Error
    #Anyhow.t_Error
    (Libcrux_ed25519.Impl_hacl.verify msg
        (Core_models.Convert.f_as_ref #Libcrux_ed25519.Impl_hacl.t_VerificationKey
            #(t_Array u8 (mk_usize 32))
            #FStar.Tactics.Typeclasses.solve
            self._0
          <:
          t_Array u8 (mk_usize 32))
        signature._0
      <:
      Core_models.Result.t_Result Prims.unit Libcrux_ed25519.Impl_hacl.t_Error)
    (fun temp_0_ ->
        let _:Libcrux_ed25519.Impl_hacl.t_Error = temp_0_ in
        let error:Anyhow.t_Error =
          Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                (let list = ["Signature verification failed"] in
                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                  Rust_primitives.Hax.array_of_list 1 list)
              <:
              Core_models.Fmt.t_Arguments)
        in
        Anyhow.__private.must_use error)
