module Hpke_rs_libcrux
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Phantom type tag selecting the libcrux-backed HPKE crypto provider,
/// parameterised by its PRNG.
assume
type t_HpkeLibcrux (v_R: Type0) : Type0

/// The default PRNG of the libcrux-backed HPKE crypto provider.
assume
type t_HpkeLibcruxPrng : Type0

/// `HpkeLibcruxPrng::try_from_seed`: instantiate the HMAC-DRBG from a
/// caller-supplied 32-byte seed. Returns error if the DRBG rejects it, which only happens when the health tests feature is enabled and the seed fails the startup health tests.
val impl_HpkeLibcruxPrng__try_from_seed (seed: t_Array u8 (mk_usize 32))
    : Prims.Pure (Core_models.Result.t_Result t_HpkeLibcruxPrng Hpke_rs_crypto.Error.t_Error)
      Prims.l_True
      (fun _ -> Prims.l_True)
