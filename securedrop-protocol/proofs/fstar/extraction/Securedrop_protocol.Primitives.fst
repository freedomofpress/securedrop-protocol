module Securedrop_protocol.Primitives
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Getrandom.Error in
  let open Hpke_rs in
  let open Hpke_rs_crypto in
  let open Hpke_rs_libcrux in
  let open Libcrux_chacha20poly1305 in
  let open Libcrux_ml_kem.Types in
  let open Rand_core in
  let open Securedrop_protocol.Primitives.Dh_akem in
  let open Securedrop_protocol.Primitives.Mlkem in
  let open Securedrop_protocol.Primitives.Xwing in
  ()

/// Fixed number of message ID entries to return in privacy-preserving fetch
/// This prevents traffic analysis by always returning the same number of entries,
/// regardless of how many actual messages exist.
let v_MESSAGE_ID_FETCH_SIZE: usize = mk_usize 10

/// Everything below here is 0.2 and will be updated / moved to the appropriate module
type t_PPKPrivateKey =
  | PPKPrivateKey : Securedrop_protocol.Primitives.X25519.t_DHPrivateKey -> t_PPKPrivateKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Core_models.Fmt.t_Debug t_PPKPrivateKey

unfold
let impl_2 = impl_2'

let impl_3: Core_models.Clone.t_Clone t_PPKPrivateKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

type t_PPKPublicKey =
  | PPKPublicKey : Securedrop_protocol.Primitives.X25519.t_DHPublicKey -> t_PPKPublicKey

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Core_models.Fmt.t_Debug t_PPKPublicKey

unfold
let impl_4 = impl_4'

let impl_5: Core_models.Clone.t_Clone t_PPKPublicKey =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

let impl_PPKPublicKey__new (public_key: Securedrop_protocol.Primitives.X25519.t_DHPublicKey)
    : t_PPKPublicKey = PPKPublicKey public_key <: t_PPKPublicKey

let impl_PPKPublicKey__into_bytes (self: t_PPKPublicKey) : t_Array u8 (mk_usize 32) =
  Securedrop_protocol.Primitives.X25519.impl_DHPublicKey__into_bytes self._0

let impl_PPKPublicKey__from_bytes (bytes: t_Array u8 (mk_usize 32)) : t_PPKPublicKey =
  PPKPublicKey (Securedrop_protocol.Primitives.X25519.impl_DHPublicKey__from_bytes bytes)
  <:
  t_PPKPublicKey

let impl_PPKPrivateKey__new (private_key: Securedrop_protocol.Primitives.X25519.t_DHPrivateKey)
    : t_PPKPrivateKey = PPKPrivateKey private_key <: t_PPKPrivateKey

let impl_PPKPrivateKey__into_bytes (self: t_PPKPrivateKey) : t_Array u8 (mk_usize 32) =
  Securedrop_protocol.Primitives.X25519.impl_DHPrivateKey__into_bytes self._0

let impl_PPKPrivateKey__from_bytes (bytes: t_Array u8 (mk_usize 32)) : t_PPKPrivateKey =
  PPKPrivateKey (Securedrop_protocol.Primitives.X25519.impl_DHPrivateKey__from_bytes bytes)
  <:
  t_PPKPrivateKey

/// This implements HPKE AuthEnc with a PSK mode as specified in the SecureDrop protocol
/// using the sender's DH-AKEM private key and the recipient's DH-AKEM pubkey
/// and PQ KEM PSK pubkey.
/// TODO: One-shot hpke API
/// TODO: Horrible types in return value
let auth_encrypt
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (rng: v_R)
      (sender_dhakem_sk: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey)
      (recipient_message_keys:
          (Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
            Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey))
      (message: t_Slice u8)
    : (v_R &
      Core_models.Result.t_Result
        ((Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) &
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error) =
  let (hpke: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux):Hpke_rs.t_Hpke
  Hpke_rs_libcrux.t_HpkeLibcrux =
    Hpke_rs.impl_7__new #Hpke_rs_libcrux.t_HpkeLibcrux
      (Hpke_rs.Mode_AuthPsk <: Hpke_rs.t_Mode)
      (Hpke_rs_crypto.Types.KemAlgorithm_DhKem25519 <: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (Hpke_rs_crypto.Types.KdfAlgorithm_HkdfSha256 <: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (Hpke_rs_crypto.Types.AeadAlgorithm_ChaCha20Poly1305 <: Hpke_rs_crypto.Types.t_AeadAlgorithm)
  in
  let sender_private_key:Hpke_rs.t_HpkePrivateKey =
    Hpke_rs.impl_HpkePrivateKey__new (Alloc.Slice.impl__to_vec #u8
          (Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPrivateKey__as_bytes (Core_models.Clone.f_clone
                  #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey
                  #FStar.Tactics.Typeclasses.solve
                  sender_dhakem_sk
                <:
                Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPrivateKey)
            <:
            t_Slice u8)
        <:
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  in
  let recipient_public_key:Hpke_rs.t_HpkePublicKey =
    Hpke_rs.impl_HpkePublicKey__new (Alloc.Slice.impl__to_vec #u8
          (Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPublicKey__as_bytes (Core_models.Clone.f_clone
                  #Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey
                  #FStar.Tactics.Typeclasses.solve
                  recipient_message_keys._1
                <:
                Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
            <:
            t_Slice u8)
        <:
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  in
  let recipient_pq_psk_key:Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1184) =
    Core_models.Result.impl__expect #(Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1184))
      #Core_models.Convert.t_Infallible
      (Core_models.Convert.f_try_from #(Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1184))
          #(t_Array u8 (mk_usize 1184))
          #FStar.Tactics.Typeclasses.solve
          (Securedrop_protocol.Primitives.Mlkem.impl_MLKEM768PublicKey__as_bytes (Core_models.Clone.f_clone
                  #Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey
                  #FStar.Tactics.Typeclasses.solve
                  recipient_message_keys._2
                <:
                Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey)
            <:
            t_Array u8 (mk_usize 1184))
        <:
        Core_models.Result.t_Result (Libcrux_ml_kem.Types.t_MlKemPublicKey (mk_usize 1184))
          Core_models.Convert.t_Infallible)
      "Expected mlkem768 pubkey"
  in
  let rand_seed:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let (tmp0: v_R), (tmp1: t_Array u8 (mk_usize 32)) =
    Rand_core.f_fill_bytes #v_R #FStar.Tactics.Typeclasses.solve rng rand_seed
  in
  let rng:v_R = tmp0 in
  let rand_seed:t_Array u8 (mk_usize 32) = tmp1 in
  let _:Prims.unit = () in
  let
  (psk_ct: Libcrux_ml_kem.Types.t_MlKemCiphertext (mk_usize 1088)),
  (shared_secret: t_Array u8 (mk_usize 32)) =
    Libcrux_ml_kem.Mlkem768.encapsulate recipient_pq_psk_key rand_seed
  in
  let fixed_psk_id:t_Array u8 (mk_usize 6) =
    let list = [mk_u8 80; mk_u8 83; mk_u8 75; mk_u8 95; mk_u8 73; mk_u8 68] in
    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 6);
    Rust_primitives.Hax.array_of_list 6 list
  in
  let
  (tmp0: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux),
  (out:
    Core_models.Result.t_Result
      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Hpke_rs.t_HpkeError) =
    Hpke_rs.impl_7__seal #Hpke_rs_libcrux.t_HpkeLibcrux
      hpke
      recipient_public_key
      ((let list:Prims.list u8 = [] in
          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
          Rust_primitives.Hax.array_of_list 0 list)
        <:
        t_Slice u8)
      ((let list:Prims.list u8 = [] in
          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
          Rust_primitives.Hax.array_of_list 0 list)
        <:
        t_Slice u8)
      message
      (Core_models.Option.Option_Some (shared_secret <: t_Slice u8)
        <:
        Core_models.Option.t_Option (t_Slice u8))
      (Core_models.Option.Option_Some (fixed_psk_id <: t_Slice u8)
        <:
        Core_models.Option.t_Option (t_Slice u8))
      (Core_models.Option.Option_Some sender_private_key
        <:
        Core_models.Option.t_Option Hpke_rs.t_HpkePrivateKey)
  in
  let hpke:Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux = tmp0 in
  match
    Core_models.Result.impl__map_err #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #Hpke_rs.t_HpkeError
      #Anyhow.t_Error
      out
      (fun e ->
          let e:Hpke_rs.t_HpkeError = e in
          let args:Hpke_rs.t_HpkeError = e <: Hpke_rs.t_HpkeError in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list = [Core_models.Fmt.Rt.impl__new_debug #Hpke_rs.t_HpkeError args] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          Anyhow.Error.impl__msg #Alloc.String.t_String
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                        (mk_usize 1)
                        (let list = ["HPKE seal failed: "] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                          Rust_primitives.Hax.array_of_list 1 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String)
              <:
              Alloc.String.t_String))
    <:
    Core_models.Result.t_Result
      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok (encapsulated_key, ciphertext) ->
    let hax_temp_output:Core_models.Result.t_Result
      ((Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error =
      Core_models.Result.Result_Ok
      ((Alloc.Slice.impl__to_vec #u8
            (Libcrux_ml_kem.Types.impl_6__as_slice (mk_usize 1088) psk_ct <: t_Slice u8),
          encapsulated_key
          <:
          (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)),
        ciphertext
        <:
        ((Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) &
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      <:
      Core_models.Result.t_Result
        ((Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) &
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
    in
    rng, hax_temp_output
    <:
    (v_R &
      Core_models.Result.t_Result
        ((Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) &
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result
        ((Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) &
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
    <:
    (v_R &
      Core_models.Result.t_Result
        ((Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) &
          Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)

/// This implements HPKE Base mode (unauthenticated) for metadata encryption
/// Encrypt the sender DH-AKEM pubkey to the recipient metadata pubkey/encaps key
/// using HPKE.Base mode.
/// The sender's other keys are included inside the authenticated ciphertext.
/// This key is required to open the authenticated ciphertext.
/// TODO: Use single-shot HPKE API instead of managing context
let enc
      (receipient_md_pk: Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey)
      (sender_dhakem_pk: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey)
      (c1 c2: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error =
  let (hpke: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux):Hpke_rs.t_Hpke
  Hpke_rs_libcrux.t_HpkeLibcrux =
    Hpke_rs.impl_7__new #Hpke_rs_libcrux.t_HpkeLibcrux
      (Hpke_rs.Mode_Base <: Hpke_rs.t_Mode)
      (Hpke_rs_crypto.Types.KemAlgorithm_XWingDraft06 <: Hpke_rs_crypto.Types.t_KemAlgorithm)
      (Hpke_rs_crypto.Types.KdfAlgorithm_HkdfSha256 <: Hpke_rs_crypto.Types.t_KdfAlgorithm)
      (Hpke_rs_crypto.Types.AeadAlgorithm_ChaCha20Poly1305 <: Hpke_rs_crypto.Types.t_AeadAlgorithm)
  in
  let recipient_public_key:Hpke_rs.t_HpkePublicKey =
    Hpke_rs.impl_HpkePublicKey__new (Alloc.Slice.impl__to_vec #u8
          (Securedrop_protocol.Primitives.Xwing.impl_XWingPublicKey__as_bytes (Core_models.Clone.f_clone
                  #Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey
                  #FStar.Tactics.Typeclasses.solve
                  receipient_md_pk
                <:
                Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey)
            <:
            t_Slice u8)
        <:
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
  in
  let metadata:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let metadata:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      metadata
      (Core_models.Clone.f_clone #(t_Array u8 (mk_usize 32))
          #FStar.Tactics.Typeclasses.solve
          (Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPublicKey__as_bytes sender_dhakem_pk
            <:
            t_Array u8 (mk_usize 32))
        <:
        t_Slice u8)
  in
  let metadata:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global metadata c1
  in
  let metadata:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global metadata c2
  in
  let
  (tmp0: Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux),
  (out:
    Core_models.Result.t_Result
      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Hpke_rs.t_HpkeError) =
    Hpke_rs.impl_7__seal #Hpke_rs_libcrux.t_HpkeLibcrux
      hpke
      recipient_public_key
      ((let list:Prims.list u8 = [] in
          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
          Rust_primitives.Hax.array_of_list 0 list)
        <:
        t_Slice u8)
      ((let list:Prims.list u8 = [] in
          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
          Rust_primitives.Hax.array_of_list 0 list)
        <:
        t_Slice u8)
      (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          metadata
        <:
        t_Slice u8)
      (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
      (Core_models.Option.Option_None <: Core_models.Option.t_Option (t_Slice u8))
      (Core_models.Option.Option_None <: Core_models.Option.t_Option Hpke_rs.t_HpkePrivateKey)
  in
  let hpke:Hpke_rs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux = tmp0 in
  match
    Core_models.Result.impl__map_err #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #Hpke_rs.t_HpkeError
      #Anyhow.t_Error
      out
      (fun e ->
          let e:Hpke_rs.t_HpkeError = e in
          let args:Hpke_rs.t_HpkeError = e <: Hpke_rs.t_HpkeError in
          let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
            let list = [Core_models.Fmt.Rt.impl__new_debug #Hpke_rs.t_HpkeError args] in
            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
            Rust_primitives.Hax.array_of_list 1 list
          in
          Anyhow.Error.impl__msg #Alloc.String.t_String
            (Core_models.Hint.must_use #Alloc.String.t_String
                (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                        (mk_usize 1)
                        (let list = ["HPKE context.seal failed: "] in
                          FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                          Rust_primitives.Hax.array_of_list 1 list)
                        args
                      <:
                      Core_models.Fmt.t_Arguments)
                  <:
                  Alloc.String.t_String)
              <:
              Alloc.String.t_String))
    <:
    Core_models.Result.t_Result
      (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      Anyhow.t_Error
  with
  | Core_models.Result.Result_Ok (encapsulated_key, encrypted_metadata) ->
    let result:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
    let result:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8
        #Alloc.Alloc.t_Global
        result
        (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            encapsulated_key
          <:
          t_Slice u8)
    in
    let result:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8
        #Alloc.Alloc.t_Global
        result
        (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            encrypted_metadata
          <:
          t_Slice u8)
    in
    Core_models.Result.Result_Ok result
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error

/// Symmetric encryption for message IDs using ChaCha20-Poly1305
/// This is used in step 7 for encrypting message IDs with a shared secret
let encrypt_message_id (key message_id: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error =
  if (Core_models.Slice.impl__len #u8 key <: usize) <>. Libcrux_chacha20poly1305.v_KEY_LEN
  then
    let error:Anyhow.t_Error =
      Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
            (let list = ["Invalid key length"] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core_models.Fmt.t_Arguments)
    in
    Core_models.Result.Result_Err (Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
  else
    let nonce:t_Array u8 (mk_usize 12) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 12) in
    let
    (tmp0: t_Array u8 (mk_usize 12)),
    (out: Core_models.Result.t_Result Prims.unit Getrandom.Error.t_Error) =
      Getrandom.fill nonce
    in
    let nonce:t_Array u8 (mk_usize 12) = tmp0 in
    let _:Prims.unit =
      Core_models.Result.impl__expect #Prims.unit #Getrandom.Error.t_Error out "Need randomness"
    in
    let output:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
    let output:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global output (nonce <: t_Slice u8)
    in
    let ciphertext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
      Alloc.Vec.from_elem #u8
        (mk_u8 0)
        ((Core_models.Slice.impl__len #u8 message_id <: usize) +! Libcrux_chacha20poly1305.v_TAG_LEN
          <:
          usize)
    in
    match
      Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 32))
        #Core_models.Array.t_TryFromSliceError
        #Anyhow.t_Error
        (Core_models.Convert.f_try_into #(t_Slice u8)
            #(t_Array u8 (mk_usize 32))
            #FStar.Tactics.Typeclasses.solve
            key
          <:
          Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
            Core_models.Array.t_TryFromSliceError)
        (fun temp_0_ ->
            let _:Core_models.Array.t_TryFromSliceError = temp_0_ in
            let error:Anyhow.t_Error =
              Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                    (let list = ["Key length mismatch"] in
                      FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                      Rust_primitives.Hax.array_of_list 1 list)
                  <:
                  Core_models.Fmt.t_Arguments)
            in
            Anyhow.__private.must_use error)
      <:
      Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
    with
    | Core_models.Result.Result_Ok (key_array: t_Array u8 (mk_usize 32)) ->
      let
      (tmp0: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global),
      (out:
        Core_models.Result.t_Result (t_Slice u8 & t_Array u8 (mk_usize 16))
          Libcrux_chacha20poly1305.t_AeadError) =
        Libcrux_chacha20poly1305.Impl_hacl.encrypt key_array
          message_id
          ciphertext
          ((let list:Prims.list u8 = [] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
              Rust_primitives.Hax.array_of_list 0 list)
            <:
            t_Slice u8)
          nonce
      in
      let ciphertext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = tmp0 in
      (match
          Core_models.Result.impl__map_err #(t_Slice u8 & t_Array u8 (mk_usize 16))
            #Libcrux_chacha20poly1305.t_AeadError
            #Anyhow.t_Error
            out
            (fun e ->
                let e:Libcrux_chacha20poly1305.t_AeadError = e in
                let args:Libcrux_chacha20poly1305.t_AeadError =
                  e <: Libcrux_chacha20poly1305.t_AeadError
                in
                let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
                  let list =
                    [Core_models.Fmt.Rt.impl__new_debug #Libcrux_chacha20poly1305.t_AeadError args]
                  in
                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                  Rust_primitives.Hax.array_of_list 1 list
                in
                Anyhow.Error.impl__msg #Alloc.String.t_String
                  (Core_models.Hint.must_use #Alloc.String.t_String
                      (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                              (mk_usize 1)
                              (let list = ["ChaCha20-Poly1305 encryption failed: "] in
                                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                                Rust_primitives.Hax.array_of_list 1 list)
                              args
                            <:
                            Core_models.Fmt.t_Arguments)
                        <:
                        Alloc.String.t_String)
                    <:
                    Alloc.String.t_String))
          <:
          Core_models.Result.t_Result (t_Slice u8 & t_Array u8 (mk_usize 16)) Anyhow.t_Error
        with
        | Core_models.Result.Result_Ok _ ->
          let output:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
            Alloc.Vec.impl_2__extend_from_slice #u8
              #Alloc.Alloc.t_Global
              output
              (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                  #FStar.Tactics.Typeclasses.solve
                  ciphertext
                <:
                t_Slice u8)
          in
          Core_models.Result.Result_Ok output
          <:
          Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
        | Core_models.Result.Result_Err err ->
          Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
    | Core_models.Result.Result_Err err ->
      Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error

/// Symmetric decryption for message IDs using ChaCha20-Poly1305
/// This is used in step 7 for decrypting message IDs with a shared secret
let decrypt_message_id (key encrypted_data: t_Slice u8)
    : Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error =
  if (Core_models.Slice.impl__len #u8 key <: usize) <>. Libcrux_chacha20poly1305.v_KEY_LEN
  then
    let error:Anyhow.t_Error =
      Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
            (let list = ["Invalid key length"] in
              FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
              Rust_primitives.Hax.array_of_list 1 list)
          <:
          Core_models.Fmt.t_Arguments)
    in
    Core_models.Result.Result_Err (Anyhow.__private.must_use error)
    <:
    Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
  else
    if
      (Core_models.Slice.impl__len #u8 encrypted_data <: usize) <.
      (Libcrux_chacha20poly1305.v_NONCE_LEN +! Libcrux_chacha20poly1305.v_TAG_LEN <: usize)
    then
      let error:Anyhow.t_Error =
        Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
              (let list = ["Encrypted data too short"] in
                FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                Rust_primitives.Hax.array_of_list 1 list)
            <:
            Core_models.Fmt.t_Arguments)
      in
      Core_models.Result.Result_Err (Anyhow.__private.must_use error)
      <:
      Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
    else
      match
        Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 12))
          #Core_models.Array.t_TryFromSliceError
          #Anyhow.t_Error
          (Core_models.Convert.f_try_into #(t_Slice u8)
              #(t_Array u8 (mk_usize 12))
              #FStar.Tactics.Typeclasses.solve
              (encrypted_data.[ {
                    Core_models.Ops.Range.f_end = Libcrux_chacha20poly1305.v_NONCE_LEN
                  }
                  <:
                  Core_models.Ops.Range.t_RangeTo usize ]
                <:
                t_Slice u8)
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 12))
              Core_models.Array.t_TryFromSliceError)
          (fun temp_0_ ->
              let _:Core_models.Array.t_TryFromSliceError = temp_0_ in
              let error:Anyhow.t_Error =
                Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                      (let list = ["Nonce extraction failed"] in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list)
                    <:
                    Core_models.Fmt.t_Arguments)
              in
              Anyhow.__private.must_use error)
        <:
        Core_models.Result.t_Result (t_Array u8 (mk_usize 12)) Anyhow.t_Error
      with
      | Core_models.Result.Result_Ok (nonce: t_Array u8 (mk_usize 12)) ->
        let ciphertext:t_Slice u8 =
          encrypted_data.[ { Core_models.Ops.Range.f_start = Libcrux_chacha20poly1305.v_NONCE_LEN }
            <:
            Core_models.Ops.Range.t_RangeFrom usize ]
        in
        let plaintext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
          Alloc.Vec.from_elem #u8
            (mk_u8 0)
            ((Core_models.Slice.impl__len #u8 ciphertext <: usize) -!
              Libcrux_chacha20poly1305.v_TAG_LEN
              <:
              usize)
        in
        (match
            Core_models.Result.impl__map_err #(t_Array u8 (mk_usize 32))
              #Core_models.Array.t_TryFromSliceError
              #Anyhow.t_Error
              (Core_models.Convert.f_try_into #(t_Slice u8)
                  #(t_Array u8 (mk_usize 32))
                  #FStar.Tactics.Typeclasses.solve
                  key
                <:
                Core_models.Result.t_Result (t_Array u8 (mk_usize 32))
                  Core_models.Array.t_TryFromSliceError)
              (fun temp_0_ ->
                  let _:Core_models.Array.t_TryFromSliceError = temp_0_ in
                  let error:Anyhow.t_Error =
                    Anyhow.__private.format_err (Core_models.Fmt.Rt.impl_1__new_const (mk_usize 1)
                          (let list = ["Key length mismatch"] in
                            FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                            Rust_primitives.Hax.array_of_list 1 list)
                        <:
                        Core_models.Fmt.t_Arguments)
                  in
                  Anyhow.__private.must_use error)
            <:
            Core_models.Result.t_Result (t_Array u8 (mk_usize 32)) Anyhow.t_Error
          with
          | Core_models.Result.Result_Ok (key_array: t_Array u8 (mk_usize 32)) ->
            let
            (tmp0: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global),
            (out: Core_models.Result.t_Result (t_Slice u8) Libcrux_chacha20poly1305.t_AeadError) =
              Libcrux_chacha20poly1305.Impl_hacl.decrypt key_array
                plaintext
                ciphertext
                ((let list:Prims.list u8 = [] in
                    FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 0);
                    Rust_primitives.Hax.array_of_list 0 list)
                  <:
                  t_Slice u8)
                nonce
            in
            let plaintext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = tmp0 in
            (match
                Core_models.Result.impl__map_err #(t_Slice u8)
                  #Libcrux_chacha20poly1305.t_AeadError
                  #Anyhow.t_Error
                  out
                  (fun e ->
                      let e:Libcrux_chacha20poly1305.t_AeadError = e in
                      let args:Libcrux_chacha20poly1305.t_AeadError =
                        e <: Libcrux_chacha20poly1305.t_AeadError
                      in
                      let args:t_Array Core_models.Fmt.Rt.t_Argument (mk_usize 1) =
                        let list =
                          [
                            Core_models.Fmt.Rt.impl__new_debug #Libcrux_chacha20poly1305.t_AeadError
                              args
                          ]
                        in
                        FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                        Rust_primitives.Hax.array_of_list 1 list
                      in
                      Anyhow.Error.impl__msg #Alloc.String.t_String
                        (Core_models.Hint.must_use #Alloc.String.t_String
                            (Alloc.Fmt.format (Core_models.Fmt.Rt.impl_1__new_v1 (mk_usize 1)
                                    (mk_usize 1)
                                    (let list = ["ChaCha20-Poly1305 decryption failed: "] in
                                      FStar.Pervasives.assert_norm
                                      (Prims.eq2 (List.Tot.length list) 1);
                                      Rust_primitives.Hax.array_of_list 1 list)
                                    args
                                  <:
                                  Core_models.Fmt.t_Arguments)
                              <:
                              Alloc.String.t_String)
                          <:
                          Alloc.String.t_String))
                <:
                Core_models.Result.t_Result (t_Slice u8) Anyhow.t_Error
              with
              | Core_models.Result.Result_Ok _ ->
                Core_models.Result.Result_Ok plaintext
                <:
                Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
              | Core_models.Result.Result_Err err ->
                Core_models.Result.Result_Err err
                <:
                Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
            )
          | Core_models.Result.Result_Err err ->
            Core_models.Result.Result_Err err
            <:
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error)
      | Core_models.Result.Result_Err err ->
        Core_models.Result.Result_Err err
        <:
        Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
