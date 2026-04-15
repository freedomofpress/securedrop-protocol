module Hpke_rs
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  let open Hpke_rs_crypto.Types in
  ()

/// HPKE mode of operation.
type t_Mode =
  | Mode_Base : t_Mode
  | Mode_Psk : t_Mode
  | Mode_Auth : t_Mode
  | Mode_AuthPsk : t_Mode

/// An HPKE context parameterised by a crypto provider tag (e.g. `Hpke_rs_libcrux.t_HpkeLibcrux`).
assume
type t_Hpke : Type0 -> Type0

/// Opaque HPKE error type.
assume
type t_HpkeError : Type0

[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_HpkeError_Debug: Core_models.Fmt.t_Debug t_HpkeError

/// Opaque HPKE public key.
assume
type t_HpkePublicKey : Type0

/// Opaque HPKE private key.
assume
type t_HpkePrivateKey : Type0

/// `HpkePublicKey::from(Vec<u8>)`, defined in the `hpke-rs` crate.
[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_HpkePublicKey_From_Vec
    : Core_models.Convert.t_From t_HpkePublicKey (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)

/// `HpkePrivateKey::from(Vec<u8>)`, defined in the `hpke-rs` crate.
[@@ FStar.Tactics.Typeclasses.tcinstance]
val impl_HpkePrivateKey_From_Vec
    : Core_models.Convert.t_From t_HpkePrivateKey (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)

/// Construct a new HPKE context with the given mode and algorithm triple.
val impl_7__new
      (#v_Crypto: Type0)
      (mode: t_Mode)
      (kem: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (kdf: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (aead: Hpke_rs_crypto.Types.t_AeadAlgorithm)
    : Prims.Pure (t_Hpke v_Crypto) Prims.l_True (fun _ -> Prims.l_True)

/// `HPKE.Seal` — encrypt `msg` to `pk_r`, optionally authenticated with
/// `signer_sk` and with a PSK `(psk, psk_id)`.
/// Returns the updated HPKE state and a `Result` of `(encapsulation, ciphertext)`.
val impl_7__seal
      (#v_Crypto: Type0)
      (self: t_Hpke v_Crypto)
      (pk_r: t_HpkePublicKey)
      (info: t_Slice u8)
      (aad: t_Slice u8)
      (msg: t_Slice u8)
      (psk: Core_models.Option.t_Option (t_Slice u8))
      (psk_id: Core_models.Option.t_Option (t_Slice u8))
      (signer_sk: Core_models.Option.t_Option t_HpkePrivateKey)
    : Prims.Pure (t_Hpke v_Crypto &
        Core_models.Result.t_Result
          (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          t_HpkeError)
      Prims.l_True
      (fun _ -> Prims.l_True)

/// `HPKE.Open` — decrypt `ct` against encapsulation `enc`, optionally
/// authenticated with `signer_pk` and with a PSK `(psk, psk_id)`.
val impl_7__open
      (#v_Crypto: Type0)
      (self: t_Hpke v_Crypto)
      (enc: t_Slice u8)
      (sk_r: t_HpkePrivateKey)
      (info: t_Slice u8)
      (aad: t_Slice u8)
      (ct: t_Slice u8)
      (psk: Core_models.Option.t_Option (t_Slice u8))
      (psk_id: Core_models.Option.t_Option (t_Slice u8))
      (signer_pk: Core_models.Option.t_Option t_HpkePublicKey)
    : Prims.Pure
        (Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_HpkeError)
      Prims.l_True
      (fun _ -> Prims.l_True)
