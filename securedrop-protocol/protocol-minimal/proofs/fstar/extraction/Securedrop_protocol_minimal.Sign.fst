module Securedrop_protocol_minimal.Sign
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_ed25519.Impl_hacl in
  let open Securedrop_protocol_minimal.Sign.Private in
  ()

/// Marker trait for signature domain separation.
/// Each impl encodes the ASCII tag that is prepended to every signing preimage
/// in that domain: `len(tag) || tag || msg`  (see footnote in the spec).
class t_DomainTag (v_Self: Type0) = {
  [@@@ FStar.Tactics.Typeclasses.no_method]_super_i0:Securedrop_protocol_minimal.Sign.Private.t_Sealed
  v_Self;
  f_TAG:t_Slice u8
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
let _ = fun (v_Self:Type0) {|i: t_DomainTag v_Self|} -> i._super_i0

/// Journalist self-signature over long-term public keys (step 3.1).
type t_JournalistLongTermKey = | JournalistLongTermKey : t_JournalistLongTermKey

/// Journalist self-signature over ephemeral key bundles (step 3.2).
type t_JournalistEphemeralKey = | JournalistEphemeralKey : t_JournalistEphemeralKey

/// FPF signature over the newsroom's verifying key (step 2).
type t_FpfOnNewsroom = | FpfOnNewsroom : t_FpfOnNewsroom

/// An Ed25519 signature carrying its domain at the type level.
/// A `Signature<D>` can only be verified against a message using the same
/// domain `D`, making cross-domain misuse a compile error rather than a
/// runtime failure.
type t_Signature (v_D: Type0) {| i0: t_DomainTag v_D |} = {
  f_bytes:t_Array u8 (mk_usize 64);
  f_e_phantom:Core_models.Marker.t_PhantomData (Prims.unit -> v_D)
}

let impl_13__from_bytes
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DomainTag v_D)
      (bytes: t_Array u8 (mk_usize 64))
    : t_Signature v_D =
  {
    f_bytes = bytes;
    f_e_phantom
    =
    Core_models.Marker.PhantomData <: Core_models.Marker.t_PhantomData (Prims.unit -> v_D)
  }
  <:
  t_Signature v_D

/// Construct the tagged signing preimage: `len(tag) || tag || msg`.
let tagged_preimage
      (#v_D: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: t_DomainTag v_D)
      (msg: t_Slice u8)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let tag:t_Slice u8 = f_TAG #FStar.Tactics.Typeclasses.solve in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.((Core_models.Slice.impl__len #u8 tag <: usize) <=. mk_usize 255 <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core_models.Panicking.panic_fmt (Core_models.Fmt.Rt.impl_1__new_const
                    (mk_usize 1)
                    (let list = ["tag length exceeds u8::MAX"] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                  <:
                  Core_models.Fmt.t_Arguments)
              <:
              Rust_primitives.Hax.t_Never)
      in
      ()
  in
  let _:Prims.unit =
    if true
    then
      let _:Prims.unit =
        if ~.(Core_models.Slice.Ascii.impl_slice_of_u8__is_ascii tag <: bool)
        then
          Rust_primitives.Hax.never_to_any (Core_models.Panicking.panic_fmt (Core_models.Fmt.Rt.impl_1__new_const
                    (mk_usize 1)
                    (let list = ["tag contains non-ASCII bytes"] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                  <:
                  Core_models.Fmt.t_Arguments)
              <:
              Rust_primitives.Hax.t_Never)
      in
      ()
  in
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

/// An Ed25519 verification key.
type t_VerifyingKey = | VerifyingKey : Libcrux_ed25519.Impl_hacl.t_VerificationKey -> t_VerifyingKey

/// An Ed25519 signing key.
type t_SigningKey = {
  f_vk:t_VerifyingKey;
  f_sk:Libcrux_ed25519.Impl_hacl.t_SigningKey
}

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
    securedrop_protocol_minimal::sign::t_SigningKey,
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
            core_models::result::Result_Ok(securedrop_protocol_minimal::sign::SigningKey {
                f_vk: securedrop_protocol_minimal::sign::VerifyingKey(vk),
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
      krate = "securedrop_protocol_minimal";
      parent =
      (Some { Types.contents =
              { Types.id = 0;
                value =
                { Types.index = (0, 0, None); is_local = true;
                  kind = Types.Impl {of_trait = false};
                  krate = "securedrop_protocol_minimal";
                  parent =
                  (Some { Types.contents =
                          { Types.id = 0;
                            value =
                            { Types.index = (0, 0, None); is_local = true;
                              kind = Types.Mod;
                              krate = "securedrop_protocol_minimal";
                              parent =
                              (Some { Types.contents =
                                      { Types.id = 0;
                                        value =
                                        { Types.index = (0, 0, None);
                                          is_local = true; kind = Types.Mod;
                                          krate =
                                          "securedrop_protocol_minimal";
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
                    { Types.data = Types.Impl; disambiguator = 16 }]
                  }
                }
              });
      path =
      [{ Types.data = (Types.TypeNs "sign"); disambiguator = 0 };
        { Types.data = Types.Impl; disambiguator = 16 };
        { Types.data = (Types.ValueNs "new"); disambiguator = 0 }]
      }
    };
  moved = None; suffix = None }) */
const _: () = ();
 *)

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
    Core_models.Result.impl__expect #(t_Array u8 (mk_usize 64))
      #Libcrux_ed25519.Impl_hacl.t_Error
      (Libcrux_ed25519.Impl_hacl.sign (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8
                  Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              preimage
            <:
            t_Slice u8)
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
  impl_13__from_bytes #v_D bytes
