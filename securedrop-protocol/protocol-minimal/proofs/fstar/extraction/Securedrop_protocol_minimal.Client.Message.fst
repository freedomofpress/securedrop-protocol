module Securedrop_protocol_minimal.Client.Message
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Rand_core in
  let open Securedrop_protocol_minimal.Traits in
  ()

/// Error types returned by decryption.
type t_DecryptError =
  | DecryptError_NoDecryptingKeyBundle : t_DecryptError
  | DecryptError_InvalidSenderKey : t_DecryptError
  | DecryptError_AuthDecFailed : t_DecryptError
  | DecryptError_MalformedPlaintext : t_DecryptError

let t_DecryptError_cast_to_repr (x: t_DecryptError) : isize =
  match x <: t_DecryptError with
  | DecryptError_NoDecryptingKeyBundle  -> mk_isize 0
  | DecryptError_InvalidSenderKey  -> mk_isize 1
  | DecryptError_AuthDecFailed  -> mk_isize 2
  | DecryptError_MalformedPlaintext  -> mk_isize 3

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl': Core_models.Fmt.t_Debug t_DecryptError

unfold
let impl = impl'

let impl_1: Core_models.Clone.t_Clone t_DecryptError =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Core_models.Marker.t_Copy t_DecryptError

unfold
let impl_2 = impl_2'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Core_models.Marker.t_StructuralPartialEq t_DecryptError

unfold
let impl_3 = impl_3'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Core_models.Cmp.t_PartialEq t_DecryptError t_DecryptError

unfold
let impl_4 = impl_4'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Core_models.Cmp.t_Eq t_DecryptError

unfold
let impl_5 = impl_5'

/// Error types returned by encryption.
type t_EncryptError =
  | EncryptError_AuthEncFailed : t_EncryptError
  | EncryptError_MetadataEncFailed : t_EncryptError

let t_EncryptError_cast_to_repr (x: t_EncryptError) : isize =
  match x <: t_EncryptError with
  | EncryptError_AuthEncFailed  -> mk_isize 0
  | EncryptError_MetadataEncFailed  -> mk_isize 1

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Core_models.Fmt.t_Debug t_EncryptError

unfold
let impl_7 = impl_7'

let impl_8: Core_models.Clone.t_Clone t_EncryptError =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_9': Core_models.Marker.t_Copy t_EncryptError

unfold
let impl_9 = impl_9'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_10': Core_models.Marker.t_StructuralPartialEq t_EncryptError

unfold
let impl_10 = impl_10'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_11': Core_models.Cmp.t_PartialEq t_EncryptError t_EncryptError

unfold
let impl_11 = impl_11'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_12': Core_models.Cmp.t_Eq t_EncryptError

unfold
let impl_12 = impl_12'

#push-options "--admit_smt_queries true"

/// Encrypt a message from a sender to a recipient (step 6).
/// Produces an [`Envelope`] containing:
/// - `ct^APKE`: SD-APKE ciphertext (encrypted message)
/// - `ct^PKE`: SD-PKE ciphertext (encrypted sender APKE public key)
/// - `(X, Z)`: hint for privacy-preserving message fetching
let encrypt
      (#v_R #v_Sender #v_Recipient: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i2:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_Sender)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i3:
          Securedrop_protocol_minimal.Traits.t_UserPublic v_Recipient)
      (rng: v_R)
      (sender: v_Sender)
      (plaintext: Securedrop_protocol_minimal.Client.Plaintext.t_PaddedPlaintext)
      (recipient: v_Recipient)
    : (v_R &
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Core.t_Envelope t_EncryptError) =
  let keypair_s:Securedrop_protocol_minimal.Schemes.Message.t_MessageKeyPair =
    Securedrop_protocol_minimal.Traits.f_message_auth_keypair #v_Sender
      #FStar.Tactics.Typeclasses.solve
      sender
  in
  let pk_r:Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey =
    Securedrop_protocol_minimal.Traits.f_message_enc_pk #v_Recipient
      #FStar.Tactics.Typeclasses.solve
      recipient
  in
  let pk_r_fetch:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey =
    Securedrop_protocol_minimal.Traits.f_fetch_pk #v_Recipient
      #FStar.Tactics.Typeclasses.solve
      recipient
  in
  let
  (tmp0: v_R),
  (out:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Schemes.Message.t_MessageCiphertext
      Anyhow.t_Error) =
    Securedrop_protocol_minimal.Schemes.Message.auth_enc #v_R
      rng
      keypair_s
      pk_r
      (Securedrop_protocol_minimal.Client.Plaintext.impl_PaddedPlaintext__as_bytes plaintext
        <:
        t_Slice u8)
      (Securedrop_protocol_minimal.Keys.Newsroom.v_NR_ID <: t_Slice u8)
      pk_r_fetch
  in
  let rng:v_R = tmp0 in
  match
    Core_models.Result.impl__map_err #Securedrop_protocol_minimal.Schemes.Message.t_MessageCiphertext
      #Anyhow.t_Error
      #t_EncryptError
      #(Anyhow.t_Error -> t_EncryptError)
      out
      (fun temp_0_ ->
          let _:Anyhow.t_Error = temp_0_ in
          EncryptError_AuthEncFailed <: t_EncryptError)
    <:
    Core_models.Result.t_Result Securedrop_protocol_minimal.Schemes.Message.t_MessageCiphertext
      t_EncryptError
  with
  | Core_models.Result.Result_Ok ct_apke ->
    let
    (tmp0: v_R),
    (out:
      (Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPrivateKey &
        Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey)) =
      Securedrop_protocol_minimal.Primitives.Ristretto255.generate_dh_keypair #v_R rng
    in
    let rng:v_R = tmp0 in
    let
    (hint_esk: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPrivateKey),
    (hint_epk: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey) =
      out
    in
    let (hint_sharedsecret: Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey):Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey
    =
      Securedrop_protocol_minimal.Primitives.Ristretto255.dh_shared_secret (Securedrop_protocol_minimal.Traits.f_fetch_pk
            #v_Recipient
            #FStar.Tactics.Typeclasses.solve
            recipient
          <:
          Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey)
        hint_esk
    in
    let
    (tmp0: v_R),
    (out:
      Core_models.Result.t_Result Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataCiphertext
        Anyhow.t_Error) =
      Securedrop_protocol_minimal.Schemes.Metadata.encrypt #v_R
        rng
        (Securedrop_protocol_minimal.Traits.f_message_metadata_pk #v_Recipient
            #FStar.Tactics.Typeclasses.solve
            recipient
          <:
          Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataPublicKey)
        (Securedrop_protocol_minimal.Schemes.Message.impl_MessageKeyPair__public_key keypair_s
          <:
          Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey)
    in
    let rng:v_R = tmp0 in
    (match
        Core_models.Result.impl__map_err #Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataCiphertext
          #Anyhow.t_Error
          #t_EncryptError
          #(Anyhow.t_Error -> t_EncryptError)
          out
          (fun temp_0_ ->
              let _:Anyhow.t_Error = temp_0_ in
              EncryptError_MetadataEncFailed <: t_EncryptError)
        <:
        Core_models.Result.t_Result
          Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataCiphertext t_EncryptError
      with
      | Core_models.Result.Result_Ok ct_pke ->
        let hax_temp_output:Core_models.Result.t_Result
          Securedrop_protocol_minimal.Wire.Core.t_Envelope t_EncryptError =
          Core_models.Result.Result_Ok
          ({
              Securedrop_protocol_minimal.Wire.Core.f_ct_apke = ct_apke;
              Securedrop_protocol_minimal.Wire.Core.f_ct_pke = ct_pke;
              Securedrop_protocol_minimal.Wire.Core.f_mgdh_pubkey = hint_epk;
              Securedrop_protocol_minimal.Wire.Core.f_mgdh = hint_sharedsecret
            }
            <:
            Securedrop_protocol_minimal.Wire.Core.t_Envelope)
          <:
          Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Core.t_Envelope
            t_EncryptError
        in
        rng, hax_temp_output
        <:
        (v_R &
          Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Core.t_Envelope
            t_EncryptError)
      | Core_models.Result.Result_Err err ->
        rng,
        (Core_models.Result.Result_Err err
          <:
          Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Core.t_Envelope
            t_EncryptError)
        <:
        (v_R &
          Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Core.t_Envelope
            t_EncryptError))
  | Core_models.Result.Result_Err err ->
    rng,
    (Core_models.Result.Result_Err err
      <:
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Core.t_Envelope t_EncryptError)
    <:
    (v_R &
      Core_models.Result.t_Result Securedrop_protocol_minimal.Wire.Core.t_Envelope t_EncryptError)

#pop-options

#push-options "--admit_smt_queries true"

/// Decrypt like [`decrypt`], additionally returning the sender's long-term
/// SD-APKE public key `pk_S^APKE` recovered from `ct^PKE`.
let decrypt_with_sender
      (#v_U: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i0:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_U)
      (receiver: v_U)
      (envelope: Securedrop_protocol_minimal.Wire.Core.t_Envelope)
    : Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext &
        Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey) t_DecryptError =
  let
  (_: Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle),
  (out:
    Core_models.Option.t_Option
    (Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle &
      Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)) =
    Core_models.Iter.Traits.Iterator.f_find_map #(Core_models.Slice.Iter.t_Iter
        Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle)
      #FStar.Tactics.Typeclasses.solve
      #(Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #(Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle
          -> Core_models.Option.t_Option
            (Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle &
              Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
      (Core_models.Slice.impl__iter #Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle
          (Alloc.Vec.impl_1__as_slice (Securedrop_protocol_minimal.Traits.f_keybundles #v_U
                  #FStar.Tactics.Typeclasses.solve
                  receiver
                <:
                Alloc.Vec.t_Vec Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle
                  Alloc.Alloc.t_Global)
            <:
            t_Slice Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle)
        <:
        Core_models.Slice.Iter.t_Iter Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle)
      (fun bundle ->
          let bundle:Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle = bundle in
          Core_models.Option.impl__map #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #(Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle &
              Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
            #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
                -> (Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle &
                    Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
            (Core_models.Result.impl__ok #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                #Anyhow.t_Error
                (Securedrop_protocol_minimal.Schemes.Metadata.decrypt (Securedrop_protocol_minimal.Schemes.Metadata.impl_MetadataKeyPair__private_key
                        bundle.Securedrop_protocol_minimal.Keys.Bundle.f_metadata_kp
                      <:
                      Securedrop_protocol_minimal.Schemes.Metadata.t_MetadataPrivateKey)
                    envelope.Securedrop_protocol_minimal.Wire.Core.f_ct_pke
                  <:
                  Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
                    Anyhow.t_Error)
              <:
              Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
            (fun m ->
                let m:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = m in
                bundle, m
                <:
                (Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle &
                  Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
          <:
          Core_models.Option.t_Option
          (Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle &
            Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global))
  in
  match
    Core_models.Option.impl__ok_or #(Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      #t_DecryptError
      out
      (DecryptError_NoDecryptingKeyBundle <: t_DecryptError)
    <:
    Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Keys.Bundle.t_MessageKeyBundle &
        Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_DecryptError
  with
  | Core_models.Result.Result_Ok (bundle, raw_metadata) ->
    (match
        Core_models.Result.impl__map_err #Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey
          #Anyhow.t_Error
          #t_DecryptError
          #(Anyhow.t_Error -> t_DecryptError)
          (Securedrop_protocol_minimal.Schemes.Message.impl_MessagePublicKey__from_bytes (Alloc.Vec.impl_1__as_slice
                  raw_metadata
                <:
                t_Slice u8)
            <:
            Core_models.Result.t_Result
              Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey Anyhow.t_Error)
          (fun temp_0_ ->
              let _:Anyhow.t_Error = temp_0_ in
              DecryptError_InvalidSenderKey <: t_DecryptError)
        <:
        Core_models.Result.t_Result Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey
          t_DecryptError
      with
      | Core_models.Result.Result_Ok sender_pk ->
        let pk_r_fetch:Securedrop_protocol_minimal.Primitives.Ristretto255.t_DHPublicKey =
          (Securedrop_protocol_minimal.Traits.f_fetch_keypair #v_U
              #FStar.Tactics.Typeclasses.solve
              receiver)
            ._2
        in
        (match
            Core_models.Result.impl__map_err #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
              #Anyhow.t_Error
              #t_DecryptError
              #(Anyhow.t_Error -> t_DecryptError)
              (Securedrop_protocol_minimal.Schemes.Message.auth_dec (Securedrop_protocol_minimal.Schemes.Message.impl_MessageKeyPair__private_key
                      bundle.Securedrop_protocol_minimal.Keys.Bundle.f_apke
                    <:
                    Securedrop_protocol_minimal.Schemes.Message.t_MessagePrivateKey)
                  sender_pk
                  envelope.Securedrop_protocol_minimal.Wire.Core.f_ct_apke
                  (Securedrop_protocol_minimal.Keys.Newsroom.v_NR_ID <: t_Slice u8)
                  pk_r_fetch
                <:
                Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Anyhow.t_Error
              )
              (fun temp_0_ ->
                  let _:Anyhow.t_Error = temp_0_ in
                  DecryptError_AuthDecFailed <: t_DecryptError)
            <:
            Core_models.Result.t_Result (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) t_DecryptError
          with
          | Core_models.Result.Result_Ok pt ->
            (match
                Core_models.Result.impl__map_err #Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext
                  #Anyhow.t_Error
                  #t_DecryptError
                  #(Anyhow.t_Error -> t_DecryptError)
                  (Core_models.Result.impl__and_then #Securedrop_protocol_minimal.Client.Plaintext.t_PaddedPlaintext
                      #Anyhow.t_Error
                      #Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext
                      #(Securedrop_protocol_minimal.Client.Plaintext.t_PaddedPlaintext
                          -> Core_models.Result.t_Result
                              Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext
                              Anyhow.t_Error)
                      (Securedrop_protocol_minimal.Client.Plaintext.impl_PaddedPlaintext__from_bytes
                          pt
                        <:
                        Core_models.Result.t_Result
                          Securedrop_protocol_minimal.Client.Plaintext.t_PaddedPlaintext
                          Anyhow.t_Error)
                      (fun padded ->
                          let padded:Securedrop_protocol_minimal.Client.Plaintext.t_PaddedPlaintext
                          =
                            padded
                          in
                          Securedrop_protocol_minimal.Client.Plaintext.impl_PaddedPlaintext__unpad padded

                          <:
                          Core_models.Result.t_Result
                            Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext Anyhow.t_Error)
                    <:
                    Core_models.Result.t_Result
                      Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext Anyhow.t_Error)
                  (fun temp_0_ ->
                      let _:Anyhow.t_Error = temp_0_ in
                      DecryptError_MalformedPlaintext <: t_DecryptError)
                <:
                Core_models.Result.t_Result Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext
                  t_DecryptError
              with
              | Core_models.Result.Result_Ok plaintext ->
                Core_models.Result.Result_Ok
                (plaintext, sender_pk
                  <:
                  (Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext &
                    Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey))
                <:
                Core_models.Result.t_Result
                  (Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext &
                    Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey) t_DecryptError
              | Core_models.Result.Result_Err err ->
                Core_models.Result.Result_Err err
                <:
                Core_models.Result.t_Result
                  (Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext &
                    Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey) t_DecryptError)
          | Core_models.Result.Result_Err err ->
            Core_models.Result.Result_Err err
            <:
            Core_models.Result.t_Result
              (Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext &
                Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey) t_DecryptError)
      | Core_models.Result.Result_Err err ->
        Core_models.Result.Result_Err err
        <:
        Core_models.Result.t_Result
          (Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext &
            Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey) t_DecryptError)
  | Core_models.Result.Result_Err err ->
    Core_models.Result.Result_Err err
    <:
    Core_models.Result.t_Result
      (Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext &
        Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey) t_DecryptError

#pop-options

#push-options "--admit_smt_queries true"

let decrypt
      (#v_U: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()]
          i0:
          Securedrop_protocol_minimal.Traits.t_UserSecret v_U)
      (receiver: v_U)
      (envelope: Securedrop_protocol_minimal.Wire.Core.t_Envelope)
    : Core_models.Result.t_Result Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext
      t_DecryptError =
  Core_models.Result.impl__map #(Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext &
      Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey)
    #t_DecryptError
    #Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext
    #(
          (Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext &
              Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey)
        -> Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext)
    (decrypt_with_sender #v_U receiver envelope
      <:
      Core_models.Result.t_Result
        (Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext &
          Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey) t_DecryptError)
    (fun temp_0_ ->
        let
        (p: Securedrop_protocol_minimal.Client.Plaintext.t_Plaintext),
        (_: Securedrop_protocol_minimal.Schemes.Message.t_MessagePublicKey) =
          temp_0_
        in
        p)

#pop-options
