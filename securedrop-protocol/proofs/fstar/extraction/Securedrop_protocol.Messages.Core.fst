module Securedrop_protocol.Messages.Core
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Sealed metadata bytes
type t_SealedMessageMetadata = | SealedMessageMetadata : t_SealedMessageMetadata

/// Metadata for decrypting ciphertext
/// TODO: check int sizes
type t_MessageMetadata = {
  f_sender_key:Securedrop_protocol.Primitives.X25519.t_DHPublicKey;
  f_message_dhakem_secret_encaps:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_message_psk_secret_encaps:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

/// Ciphertext bytes
type t_SealedMessage = | SealedMessage : t_SealedMessage

type t_SealedEnvelope = {
  f_sealed_message:t_SealedMessage;
  f_sealed_metadata:t_SealedMessageMetadata;
  f_metadata_encaps:Alloc.Vec.t_Vec u16 Alloc.Alloc.t_Global
}

/// TODO: Plaintext message structure (i.e what keys or hashes of keys are included?)
/// At minimum:
/// Sender XWING key (for replies metadata)
/// Sender MLKEM key (for replies)
/// Identifiers: newsroom identifier
/// Fetching key identifier?
/// DH-AKEM key identifier (maybe not needed bc of how auth mode in hpke works)?
/// Plaintext
/// (Z, X)
type t_MessageClue = {
  f_clue_bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_clue_pubkey:Securedrop_protocol.Primitives.X25519.t_DHPublicKey
}

type t_MessageBundle = {
  f_sealed_envelope:t_SealedEnvelope;
  f_message_clue:t_MessageClue
}

/// Source fetches keys for the newsroom
/// This is the first request in step 5 of the spec.
type t_SourceNewsroomKeyRequest = | SourceNewsroomKeyRequest : t_SourceNewsroomKeyRequest

/// Newsroom returns their keys and proof of onboarding.
/// This is the first response in step 5 of the spec.
type t_SourceNewsroomKeyResponse = {
  f_newsroom_verifying_key:Securedrop_protocol.Sign.t_VerifyingKey;
  f_fpf_sig:Securedrop_protocol.Sign.t_Signature
}

/// Source fetches journalist keys for the newsroom
/// This is part of step 5 in the spec.
/// Note: This isn't currently written down in the spec, but
/// should occur right before the server provides a long-term
/// key and an ephmeral key bundle for the journalist.
type t_SourceJournalistKeyRequest = | SourceJournalistKeyRequest : t_SourceJournalistKeyRequest

/// Server returns journalist long-term keys and ephemeral keys
/// This is the second part of step 5 in the spec.
/// Updated for 0.3 spec with new key types:
/// - ephemeral_dh_pk: MLKEM-768 for message enc PSK (one-time)
/// - ephemeral_kem_pk: DH-AKEM for message enc (one-time)
/// - ephemeral_pke_pk: XWING for metadata enc (one-time)
/// TODO: this may be split into 2 responses, one that contains
/// static keys and one that contains one-time keys
type t_SourceJournalistKeyResponse = {
  f_journalist_sig_pk:Securedrop_protocol.Sign.t_VerifyingKey;
  f_journalist_fetch_pk:Securedrop_protocol.Primitives.X25519.t_DHPublicKey;
  f_journalist_dhakem_sending_pk:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_newsroom_sig:Securedrop_protocol.Sign.t_Signature;
  f_one_time_message_pq_pk:Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey;
  f_one_time_message_pk:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_one_time_metadata_pk:Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey;
  f_journalist_ephemeral_sig:Securedrop_protocol.Sign.t_Signature;
  f_journalist_self_sig:Securedrop_protocol.Sign.t_SelfSignature
}

/// Message structure for Step 6: Source submits a message
/// This represents the message format before padding and encryption:
/// `source_message_pq_pk || source_message_pk || source_metadata_pk || S_fetch,pk || J^i_sig,pk || NR || msg`
/// TODO: Decide on actual format
/// TODO: Just include a hash of the DH-AKEM public key, 0.3 description suggests that
type t_SourceMessage = {
  f_message:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_source_message_pq_pk:Securedrop_protocol.Primitives.Mlkem.t_MLKEM768PublicKey;
  f_source_message_pk:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_source_metadata_pk:Securedrop_protocol.Primitives.Xwing.t_XWingPublicKey;
  f_source_fetch_pk:Securedrop_protocol.Primitives.X25519.t_DHPublicKey;
  f_journalist_sig_pk:Securedrop_protocol.Sign.t_VerifyingKey;
  f_newsroom_sig_pk:Securedrop_protocol.Sign.t_VerifyingKey
}

let impl_4: Core_models.Clone.t_Clone t_SourceMessage =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Serialize the message into bytes for padding and encryption
/// Note: Deviated from 0.2 spec here to put variable length field last
let impl_SourceMessage__into_bytes (self: t_SourceMessage) : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let (bytes: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global):Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl__new #u8 ()
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Primitives.Mlkem.impl_MLKEM768PublicKey__as_bytes self
              .f_source_message_pq_pk
          <:
          t_Array u8 (mk_usize 1184)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 1184
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPublicKey__as_bytes self
              .f_source_message_pk
          <:
          t_Array u8 (mk_usize 32)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 32
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Primitives.Xwing.impl_XWingPublicKey__as_bytes self.f_source_metadata_pk
          <:
          t_Array u8 (mk_usize 1216)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 1216
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Primitives.X25519.impl_DHPublicKey__into_bytes self.f_source_fetch_pk
          <:
          t_Array u8 (mk_usize 32)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 32
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Sign.impl_VerifyingKey__into_bytes self.f_journalist_sig_pk
          <:
          t_Array u8 (mk_usize 32)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 32
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Sign.impl_VerifyingKey__into_bytes self.f_newsroom_sig_pk
          <:
          t_Array u8 (mk_usize 32)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 32
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          self.f_message
        <:
        t_Slice u8)
  in
  bytes

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1: Securedrop_protocol.Client.t_StructuredMessage t_SourceMessage =
  {
    f_into_bytes_pre = (fun (self: t_SourceMessage) -> true);
    f_into_bytes_post
    =
    (fun (self: t_SourceMessage) (out: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_into_bytes = fun (self: t_SourceMessage) -> impl_SourceMessage__into_bytes self
  }

/// Message structure for Step 9: Journalist replies to a source
/// This represents the message format before padding and encryption:
/// `msg || S || J_sig,pk || J_fetch,pk || J_dh,pk || σ^NR || NR`
/// TODO: some of the signature information won't be per-message, but may
/// be part of a prior per-session fetch. Added self-signature over long-term
/// keys to message structure for now.
type t_JournalistReplyMessage = {
  f_message:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_source:Uuid.t_Uuid;
  f_journalist_sig_pk:Securedrop_protocol.Sign.t_VerifyingKey;
  f_journalist_fetch_pk:Securedrop_protocol.Primitives.X25519.t_DHPublicKey;
  f_journalist_reply_pk:Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey;
  f_newsroom_signature:Securedrop_protocol.Sign.t_Signature;
  f_newsroom_sig_pk:Securedrop_protocol.Sign.t_VerifyingKey;
  f_self_signature:Securedrop_protocol.Sign.t_SelfSignature
}

let impl_5: Core_models.Clone.t_Clone t_JournalistReplyMessage =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// Serialize the message into bytes for padding and encryption
/// TODO: I deviated from the spec here to put the message last
/// because it's the only variable length field.
let impl_JournalistReplyMessage__into_bytes (self: t_JournalistReplyMessage)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = Alloc.Vec.impl__new #u8 () in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Uuid.impl_Uuid__as_bytes self.f_source <: t_Array u8 (mk_usize 16)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 16
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Sign.impl_VerifyingKey__into_bytes self.f_journalist_sig_pk
          <:
          t_Array u8 (mk_usize 32)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 32
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Primitives.X25519.impl_DHPublicKey__into_bytes self
              .f_journalist_fetch_pk
          <:
          t_Array u8 (mk_usize 32)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 32
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Primitives.Dh_akem.impl_DhAkemPublicKey__as_bytes self
              .f_journalist_reply_pk
          <:
          t_Array u8 (mk_usize 32)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 32
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      (self.f_newsroom_signature.Securedrop_protocol.Sign._0.[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 64
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Sign.impl_VerifyingKey__into_bytes self.f_newsroom_sig_pk
          <:
          t_Array u8 (mk_usize 32)).[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 32
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      ((Securedrop_protocol.Sign.impl_SelfSignature__as_signature self.f_self_signature
          <:
          Securedrop_protocol.Sign.t_Signature)
          .Securedrop_protocol.Sign._0.[ {
            Core_models.Ops.Range.f_start = mk_usize 0;
            Core_models.Ops.Range.f_end = mk_usize 64
          }
          <:
          Core_models.Ops.Range.t_Range usize ]
        <:
        t_Slice u8)
  in
  let bytes:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      bytes
      (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          self.f_message
        <:
        t_Slice u8)
  in
  bytes

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_3: Securedrop_protocol.Client.t_StructuredMessage t_JournalistReplyMessage =
  {
    f_into_bytes_pre = (fun (self: t_JournalistReplyMessage) -> true);
    f_into_bytes_post
    =
    (fun (self: t_JournalistReplyMessage) (out: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) -> true);
    f_into_bytes
    =
    fun (self: t_JournalistReplyMessage) -> impl_JournalistReplyMessage__into_bytes self
  }

type t_Message = {
  f_ciphertext:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_dh_share_z:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global;
  f_dh_share_x:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
}

let impl_6: Core_models.Clone.t_Clone t_Message =
  { f_clone = (fun x -> x); f_clone_pre = (fun _ -> True); f_clone_post = (fun _ _ -> True) }

/// User (source or journalist) fetches message IDs
/// This corresponds to step 7 in the spec.
type t_MessageChallengeFetchRequest =
  | MessageChallengeFetchRequest : t_MessageChallengeFetchRequest

/// Server returns encrypted message IDs
/// This corresponds to step 7 in the spec.
type t_MessageChallengeFetchResponse = {
  f_count:usize;
  f_messages:Alloc.Vec.t_Vec
    (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global & Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
    Alloc.Alloc.t_Global
}

/// User fetches a specific message by ID
/// This corresponds to step 8 and 10 in the spec.
type t_MessageFetchRequest = { f_message_id:u64 }
