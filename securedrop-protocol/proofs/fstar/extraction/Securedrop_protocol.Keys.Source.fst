module Securedrop_protocol.Keys.Source
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Anyhow.Error in
  let open Blake2 in
  let open Block_buffer in
  let open Digest in
  let open Digest.Core_api in
  let open Digest.Core_api.Ct_variable in
  let open Digest.Core_api.Wrapper in
  let open Digest.Digest in
  let open Generic_array in
  let open Generic_array.Impls in
  let open Libcrux_ml_kem.Types in
  let open Rand_core in
  let open Securedrop_protocol.Primitives in
  let open Securedrop_protocol.Primitives.X25519 in
  let open Typenum in
  let open Typenum.Bit in
  let open Typenum.Marker_traits in
  let open Typenum.Private in
  let open Typenum.Type_operators in
  let open Typenum.Uint in
  ()

/// This contains the sender keys for the source, provided during their message submission.
/// The DH-AKEM public key is provided in the outer metadata, and is needed to
/// decrypt the inner authenticated ciphertext.
/// The metadata key, PQ PSK key, and Fetching key are provided so that sources
/// can receive replies.
type t_SourcePublicKeys = {
  f_message_dhakem_pk:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_message_pq_psk_pk:Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey;
  f_metadata_pk:Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey;
  f_fetch_pk:Securedrop_protocol.Primitives.X25519.t_DHPublicKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_8': Core_models.Fmt.t_Debug t_SourcePublicKeys

unfold
let impl_8 = impl_8'

let impl_9: Core_models.Clone.t_Clone t_SourcePublicKeys =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

type t_SourcePassphrase = { f_passphrase:t_Array u8 (mk_usize 32) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_12': Core_models.Fmt.t_Debug t_SourcePassphrase

unfold
let impl_12 = impl_12'

let impl_13: Core_models.Clone.t_Clone t_SourcePassphrase =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

type t_SourceFetchKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.X25519.t_DHPublicKey;
  f_private_key:Securedrop_protocol.Primitives.X25519.t_DHPrivateKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_14': Core_models.Fmt.t_Debug t_SourceFetchKeyPair

unfold
let impl_14 = impl_14'

let impl_15: Core_models.Clone.t_Clone t_SourceFetchKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Create a fetch key pair from private key bytes
let impl_SourceFetchKeyPair__new (private_key_bytes: t_Array u8 (mk_usize 32))
    : t_SourceFetchKeyPair =
  let
  (private_key: Securedrop_protocol.Primitives.X25519.t_DHPrivateKey),
  (public_key: Securedrop_protocol.Primitives.X25519.t_DHPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
        Securedrop_protocol.Primitives.X25519.t_DHPublicKey)
      #Anyhow.t_Error
      (Securedrop_protocol.Primitives.X25519.deterministic_dh_keygen private_key_bytes
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol.Primitives.X25519.t_DHPrivateKey &
            Securedrop_protocol.Primitives.X25519.t_DHPublicKey) Anyhow.t_Error)
      "Failed to generate DH keypair"
  in
  { f_public_key = public_key; f_private_key = private_key } <: t_SourceFetchKeyPair

/// Get the public key as bytes
let impl_SourceFetchKeyPair__public_key_bytes (self: t_SourceFetchKeyPair)
    : t_Array u8 (mk_usize 32) =
  Securedrop_protocol.Primitives.X25519.impl_DHPublicKey__into_bytes (Core_models.Clone.f_clone #Securedrop_protocol.Primitives.X25519.t_DHPublicKey
        #FStar.Tactics.Typeclasses.solve
        self.f_public_key
      <:
      Securedrop_protocol.Primitives.X25519.t_DHPublicKey)

type t_SourceDHKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.X25519.t_DHPublicKey;
  f_private_key:Securedrop_protocol.Primitives.X25519.t_DHPrivateKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_16': Core_models.Fmt.t_Debug t_SourceDHKeyPair

unfold
let impl_16 = impl_16'

let impl_17: Core_models.Clone.t_Clone t_SourceDHKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Create a DH key pair from private key bytes
let impl_SourceDHKeyPair__new (private_key_bytes: t_Array u8 (mk_usize 32)) : t_SourceDHKeyPair =
  let private_key:Securedrop_protocol.Primitives.X25519.t_DHPrivateKey =
    Securedrop_protocol.Primitives.X25519.impl_DHPrivateKey__from_bytes private_key_bytes
  in
  let public_key_bytes:t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let public_key_bytes:t_Array u8 (mk_usize 32) =
    Libcrux_curve25519.Impl_hacl.secret_to_public public_key_bytes private_key_bytes
  in
  let public_key:Securedrop_protocol.Primitives.X25519.t_DHPublicKey =
    Securedrop_protocol.Primitives.X25519.impl_DHPublicKey__from_bytes public_key_bytes
  in
  { f_public_key = public_key; f_private_key = private_key } <: t_SourceDHKeyPair

/// Get the public key as bytes
let impl_SourceDHKeyPair__public_key_bytes (self: t_SourceDHKeyPair) : t_Array u8 (mk_usize 32) =
  Securedrop_protocol.Primitives.X25519.impl_DHPublicKey__into_bytes (Core_models.Clone.f_clone #Securedrop_protocol.Primitives.X25519.t_DHPublicKey
        #FStar.Tactics.Typeclasses.solve
        self.f_public_key
      <:
      Securedrop_protocol.Primitives.X25519.t_DHPublicKey)

type t_SourceKEMKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.t_PPKPublicKey;
  f_private_key:Securedrop_protocol.Primitives.t_PPKPrivateKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_18': Core_models.Fmt.t_Debug t_SourceKEMKeyPair

unfold
let impl_18 = impl_18'

let impl_19: Core_models.Clone.t_Clone t_SourceKEMKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Create a KEM key pair from private key bytes
let impl_SourceKEMKeyPair__new (private_key_bytes: t_Array u8 (mk_usize 32)) : t_SourceKEMKeyPair =
  let private_key:Securedrop_protocol.Primitives.t_PPKPrivateKey =
    Securedrop_protocol.Primitives.impl_PPKPrivateKey__new (Securedrop_protocol.Primitives.X25519.impl_DHPrivateKey__from_bytes
          private_key_bytes
        <:
        Securedrop_protocol.Primitives.X25519.t_DHPrivateKey)
  in
  let public_key_bytes:t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let public_key_bytes:t_Array u8 (mk_usize 32) =
    Libcrux_curve25519.Impl_hacl.secret_to_public public_key_bytes private_key_bytes
  in
  let public_key:Securedrop_protocol.Primitives.t_PPKPublicKey =
    Securedrop_protocol.Primitives.impl_PPKPublicKey__new (Securedrop_protocol.Primitives.X25519.impl_DHPublicKey__from_bytes
          public_key_bytes
        <:
        Securedrop_protocol.Primitives.X25519.t_DHPublicKey)
  in
  { f_public_key = public_key; f_private_key = private_key } <: t_SourceKEMKeyPair

/// Get the public key as bytes
let impl_SourceKEMKeyPair__public_key_bytes (self: t_SourceKEMKeyPair) : t_Array u8 (mk_usize 32) =
  Securedrop_protocol.Primitives.impl_PPKPublicKey__into_bytes (Core_models.Clone.f_clone #Securedrop_protocol.Primitives.t_PPKPublicKey
        #FStar.Tactics.Typeclasses.solve
        self.f_public_key
      <:
      Securedrop_protocol.Primitives.t_PPKPublicKey)

type t_SourcePKEKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.t_PPKPublicKey;
  f_private_key:Securedrop_protocol.Primitives.t_PPKPrivateKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_20': Core_models.Fmt.t_Debug t_SourcePKEKeyPair

unfold
let impl_20 = impl_20'

let impl_21: Core_models.Clone.t_Clone t_SourcePKEKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Create a PKE key pair from private key bytes
let impl_SourcePKEKeyPair__new (private_key_bytes: t_Array u8 (mk_usize 32)) : t_SourcePKEKeyPair =
  let private_key:Securedrop_protocol.Primitives.t_PPKPrivateKey =
    Securedrop_protocol.Primitives.impl_PPKPrivateKey__new (Securedrop_protocol.Primitives.X25519.impl_DHPrivateKey__from_bytes
          private_key_bytes
        <:
        Securedrop_protocol.Primitives.X25519.t_DHPrivateKey)
  in
  let public_key_bytes:t_Array u8 (mk_usize 32) =
    Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32)
  in
  let public_key_bytes:t_Array u8 (mk_usize 32) =
    Libcrux_curve25519.Impl_hacl.secret_to_public public_key_bytes private_key_bytes
  in
  let public_key:Securedrop_protocol.Primitives.t_PPKPublicKey =
    Securedrop_protocol.Primitives.impl_PPKPublicKey__new (Securedrop_protocol.Primitives.X25519.impl_DHPublicKey__from_bytes
          public_key_bytes
        <:
        Securedrop_protocol.Primitives.X25519.t_DHPublicKey)
  in
  { f_public_key = public_key; f_private_key = private_key } <: t_SourcePKEKeyPair

/// Get the public key as bytes
let impl_SourcePKEKeyPair__public_key_bytes (self: t_SourcePKEKeyPair) : t_Array u8 (mk_usize 32) =
  Securedrop_protocol.Primitives.impl_PPKPublicKey__into_bytes (Core_models.Clone.f_clone #Securedrop_protocol.Primitives.t_PPKPublicKey
        #FStar.Tactics.Typeclasses.solve
        self.f_public_key
      <:
      Securedrop_protocol.Primitives.t_PPKPublicKey)

/// Source message encryption PSK (used for PQ secret)
/// $S_pq$ in the specification.
type t_SourceMessagePQKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey;
  f_private_key:Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_22': Core_models.Fmt.t_Debug t_SourceMessagePQKeyPair

unfold
let impl_22 = impl_22'

let impl_23: Core_models.Clone.t_Clone t_SourceMessagePQKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Given a random seed, construct MLKEM768 encaps and decaps key.
/// TODO: ***FOR PROOF OF CONCEPT ONLY!*** Not for production use.
let impl_SourceMessagePQKeyPair__from_bytes (priv_key_bytes: t_Array u8 (mk_usize 64))
    : t_SourceMessagePQKeyPair =
  let
  (sk: Libcrux_ml_kem.Types.t_MlKemPrivateKey (mk_usize 2400)),
  (pk: Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1184)) =
    Libcrux_ml_kem.Types.impl_21__into_parts (mk_usize 2400)
      (mk_usize 1184)
      (Libcrux_ml_kem.Mlkem768.generate_key_pair priv_key_bytes
        <:
        Libcrux_ml_kem.Types.t_MlKemKeyPair (mk_usize 2400) (mk_usize 1184))
  in
  let mlkem_encaps:Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey =
    Securedrop_protocol.Primitives.Mlkem.impl_MLKEM768PublicKey__from_bytes (Core_models.Convert.f_into
          #(Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1184))
          #(t_Array u8 (mk_usize 1184))
          #FStar.Tactics.Typeclasses.solve
          pk
        <:
        t_Array u8 (mk_usize 1184))
  in
  let mlkem_decaps:Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PrivateKey =
    Securedrop_protocol.Primitives.Mlkem.impl_MLKEM768PrivateKey__from_bytes (Core_models.Convert.f_into
          #(Libcrux_ml_kem.Types.t_MlKemPrivateKey (mk_usize 2400))
          #(t_Array u8 (mk_usize 2400))
          #FStar.Tactics.Typeclasses.solve
          sk
        <:
        t_Array u8 (mk_usize 2400))
  in
  { f_public_key = mlkem_encaps; f_private_key = mlkem_decaps } <: t_SourceMessagePQKeyPair

/// Source message encryption keypair (classical component)
/// $S_dh$ in the specification.
type t_SourceMessageClassicalKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_private_key:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_24': Core_models.Fmt.t_Debug t_SourceMessageClassicalKeyPair

unfold
let impl_24 = impl_24'

let impl_25: Core_models.Clone.t_Clone t_SourceMessageClassicalKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Given a random seed, construct XWING encaps and decaps key.
/// TODO: ***FOR PROOF OF CONCEPT ONLY!*** Not for production use.
let impl_SourceMessageClassicalKeyPair__from_bytes (seed_bytes: t_Array u8 (mk_usize 32))
    : t_SourceMessageClassicalKeyPair =
  let
  (md_decaps: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey),
  (md_encaps: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey &
        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
      #Anyhow.t_Error
      (Securedrop_protocol.Primitives.Dh_akem.deterministic_keygen seed_bytes
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey &
            Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey) Anyhow.t_Error)
      "Failed to generate DH-AKEM keypair"
  in
  { f_public_key = md_encaps; f_private_key = md_decaps } <: t_SourceMessageClassicalKeyPair

/// Source metadata (hybrid) keypair
/// $S_md$ in the specification.
type t_SourceMetadataKeyPair = {
  f_public_key:Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey;
  f_private_key:Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey
}

type t_SourceKeyBundle = {
  f_fetch:t_SourceFetchKeyPair;
  f_message_encrypt_dhakem:t_SourceMessageClassicalKeyPair;
  f_pq_kem_psk:t_SourceMessagePQKeyPair;
  f_metadata:t_SourceMetadataKeyPair
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_10': Core_models.Fmt.t_Debug t_SourceKeyBundle

unfold
let impl_10 = impl_10'

let impl_11: Core_models.Clone.t_Clone t_SourceKeyBundle =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_26': Core_models.Fmt.t_Debug t_SourceMetadataKeyPair

unfold
let impl_26 = impl_26'

let impl_27: Core_models.Clone.t_Clone t_SourceMetadataKeyPair =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Given a random seed, construct XWING encaps and decaps key.
/// TODO: ***FOR PROOF OF CONCEPT ONLY!*** Not for production use.
let impl_SourceMetadataKeyPair__from_bytes (seed_bytes: t_Array u8 (mk_usize 32))
    : t_SourceMetadataKeyPair =
  let
  (md_decaps: Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey),
  (md_encaps: Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey) =
    Core_models.Result.impl__expect #(Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey &
        Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey)
      #Anyhow.t_Error
      (Securedrop_protocol.Primitives.Xwing.deterministic_keygen seed_bytes
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol.Primitives.Xwing.t_XWingPrivateKey &
            Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey) Anyhow.t_Error)
      "Failed to generate XWING keypair"
  in
  { f_public_key = md_encaps; f_private_key = md_decaps } <: t_SourceMetadataKeyPair

/// Get the source's DH-AKEM  public key
let impl_SourceKeyBundle__dh_public_key (self: t_SourceKeyBundle)
    : Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey =
  self.f_message_encrypt_dhakem.f_public_key

/// Get the source's metadata public key
let impl_SourceKeyBundle__pke_public_key (self: t_SourceKeyBundle)
    : Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey = self.f_metadata.f_public_key

/// Get the source's KEM public key
let impl_SourceKeyBundle__kem_public_key (self: t_SourceKeyBundle)
    : Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey = self.f_pq_kem_psk.f_public_key

/// Get the source's fetch public key
let impl_SourceKeyBundle__fetch_public_key (self: t_SourceKeyBundle)
    : Securedrop_protocol.Primitives.X25519.t_DHPublicKey = self.f_fetch.f_public_key

/// Reconstruct keys from an existing passphrase
/// TODO: What do we want to do here? This is not yet specified AFAICT
let impl_SourceKeyBundle__from_passphrase (passphrase: t_Slice u8) : t_SourceKeyBundle =
  let dh_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_new #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      ()
  in
  let dh_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 9))
      dh_hasher
      (let list =
          [mk_u8 83; mk_u8 68; mk_u8 95; mk_u8 68; mk_u8 72; mk_u8 95; mk_u8 75; mk_u8 69; mk_u8 89]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 9);
        Rust_primitives.Hax.array_of_list 9 list)
  in
  let dh_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Slice u8)
      dh_hasher
      passphrase
  in
  let dh_result:Generic_array.t_GenericArray u8
    (Typenum.Uint.t_UInt
        (Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
        Typenum.Bit.t_B0) =
    Digest.Digest.f_finalize #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      dh_hasher
  in
  let fetch_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_new #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      ()
  in
  let fetch_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 12))
      fetch_hasher
      (let list =
          [
            mk_u8 83; mk_u8 68; mk_u8 95; mk_u8 70; mk_u8 69; mk_u8 84; mk_u8 67; mk_u8 72; mk_u8 95;
            mk_u8 75; mk_u8 69; mk_u8 89
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 12);
        Rust_primitives.Hax.array_of_list 12 list)
  in
  let fetch_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Slice u8)
      fetch_hasher
      passphrase
  in
  let fetch_result:Generic_array.t_GenericArray u8
    (Typenum.Uint.t_UInt
        (Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
        Typenum.Bit.t_B0) =
    Digest.Digest.f_finalize #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      fetch_hasher
  in
  let pke_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_new #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      ()
  in
  let pke_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 10))
      pke_hasher
      (let list =
          [
            mk_u8 83; mk_u8 68; mk_u8 95; mk_u8 80; mk_u8 75; mk_u8 69; mk_u8 95; mk_u8 75; mk_u8 69;
            mk_u8 89
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 10);
        Rust_primitives.Hax.array_of_list 10 list)
  in
  let pke_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
          Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Slice u8)
      pke_hasher
      passphrase
  in
  let pke_result:Generic_array.t_GenericArray u8
    (Typenum.Uint.t_UInt
        (Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
        Typenum.Bit.t_B0) =
    Digest.Digest.f_finalize #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                    Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      pke_hasher
  in
  let kem_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                              Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0
              ) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_new #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      ()
  in
  let kem_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                              Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0
              ) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Array u8 (mk_usize 10))
      kem_hasher
      (let list =
          [
            mk_u8 83; mk_u8 68; mk_u8 95; mk_u8 75; mk_u8 69; mk_u8 77; mk_u8 95; mk_u8 75; mk_u8 69;
            mk_u8 89
          ]
        in
        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 10);
        Rust_primitives.Hax.array_of_list 10 list)
  in
  let kem_hasher:Digest.Core_api.Wrapper.t_CoreWrapper
  (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
      (Typenum.Uint.t_UInt
          (Typenum.Uint.t_UInt
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                              Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0
              ) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
      Digest.Core_api.Ct_variable.t_NoOid) =
    Digest.Digest.f_update #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      #(t_Slice u8)
      kem_hasher
      passphrase
  in
  let kem_result:Generic_array.t_GenericArray u8
    (Typenum.Uint.t_UInt
        (Typenum.Uint.t_UInt
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                            Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Typenum.Bit.t_B0) Typenum.Bit.t_B0) =
    Digest.Digest.f_finalize #(Digest.Core_api.Wrapper.t_CoreWrapper
        (Digest.Core_api.Ct_variable.t_CtVariableCoreWrapper Blake2.t_Blake2bVarCore
            (Typenum.Uint.t_UInt
                (Typenum.Uint.t_UInt
                    (Typenum.Uint.t_UInt
                        (Typenum.Uint.t_UInt
                            (Typenum.Uint.t_UInt
                                (Typenum.Uint.t_UInt
                                    (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                    Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                        Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
            Digest.Core_api.Ct_variable.t_NoOid))
      #FStar.Tactics.Typeclasses.solve
      kem_hasher
  in
  {
    f_fetch
    =
    impl_SourceFetchKeyPair__new (Core_models.Convert.f_into #(Generic_array.t_GenericArray u8
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                  Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                      Typenum.Bit.t_B0) Typenum.Bit.t_B0))
          #(t_Array u8 (mk_usize 32))
          #FStar.Tactics.Typeclasses.solve
          fetch_result
        <:
        t_Array u8 (mk_usize 32));
    f_message_encrypt_dhakem
    =
    impl_SourceMessageClassicalKeyPair__from_bytes (Core_models.Convert.f_into #(Generic_array.t_GenericArray
              u8
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                  Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                      Typenum.Bit.t_B0) Typenum.Bit.t_B0))
          #(t_Array u8 (mk_usize 32))
          #FStar.Tactics.Typeclasses.solve
          dh_result
        <:
        t_Array u8 (mk_usize 32));
    f_pq_kem_psk
    =
    impl_SourceMessagePQKeyPair__from_bytes (Core_models.Convert.f_into #(Generic_array.t_GenericArray
              u8
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt
                                      (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                      Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                          Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0))
          #(t_Array u8 (mk_usize 64))
          #FStar.Tactics.Typeclasses.solve
          kem_result
        <:
        t_Array u8 (mk_usize 64));
    f_metadata
    =
    impl_SourceMetadataKeyPair__from_bytes (Core_models.Convert.f_into #(Generic_array.t_GenericArray
              u8
              (Typenum.Uint.t_UInt
                  (Typenum.Uint.t_UInt
                      (Typenum.Uint.t_UInt
                          (Typenum.Uint.t_UInt
                              (Typenum.Uint.t_UInt
                                  (Typenum.Uint.t_UInt Typenum.Uint.t_UTerm Typenum.Bit.t_B1)
                                  Typenum.Bit.t_B0) Typenum.Bit.t_B0) Typenum.Bit.t_B0)
                      Typenum.Bit.t_B0) Typenum.Bit.t_B0))
          #(t_Array u8 (mk_usize 32))
          #FStar.Tactics.Typeclasses.solve
          pke_result
        <:
        t_Array u8 (mk_usize 32))
  }
  <:
  t_SourceKeyBundle

let impl_SourceKeyBundle__new
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
    : (t_SourcePassphrase & t_SourceKeyBundle) =
  let passphrase:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 32)) =
    Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng passphrase
  in
  let rng:v_R = tmp0 in
  let passphrase:t_Array u8 (mk_usize 32) = tmp1 in
  let _:Prims.unit = () in
  let source_passphrase:t_SourcePassphrase = { f_passphrase = passphrase } <: t_SourcePassphrase in
  let key_bundle:t_SourceKeyBundle =
    impl_SourceKeyBundle__from_passphrase (passphrase <: t_Slice u8)
  in
  source_passphrase, key_bundle <: (t_SourcePassphrase & t_SourceKeyBundle)
