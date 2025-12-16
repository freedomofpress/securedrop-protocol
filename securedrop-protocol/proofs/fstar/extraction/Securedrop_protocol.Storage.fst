module Securedrop_protocol.Storage
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Ahash in
  let open Ahash.Fallback_hash in
  let open Allocator_api2.Stable.Alloc in
  let open Allocator_api2.Stable.Alloc.Global in
  let open Hashbrown in
  let open Hashbrown.Map in
  let open Rand_core in
  let open Uuid in
  ()

type t_ServerStorage = {
  f_journalists:Hashbrown.Map.t_HashMap Uuid.t_Uuid
    (Securedrop_protocol.Sign.t_VerifyingKey & Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
      Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
      Securedrop_protocol.Sign.t_SelfSignature &
      Securedrop_protocol.Sign.t_Signature)
    (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
    Allocator_api2.Stable.Alloc.Global.t_Global;
  f_ephemeral_keys:Hashbrown.Map.t_HashMap Uuid.t_Uuid
    (Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
        Alloc.Alloc.t_Global)
    (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
    Allocator_api2.Stable.Alloc.Global.t_Global;
  f_messages:Hashbrown.Map.t_HashMap Uuid.t_Uuid
    Securedrop_protocol.Messages.Core.t_Message
    (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
    Allocator_api2.Stable.Alloc.Global.t_Global
}

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_1': Core_models.Default.t_Default t_ServerStorage

unfold
let impl_1 = impl_1'

/// Create a new ServerStorage instance
let impl_ServerStorage__new (_: Prims.unit) : t_ServerStorage =
  Core_models.Default.f_default #t_ServerStorage #FStar.Tactics.Typeclasses.solve ()

/// Add ephemeral keys for a journalist
let impl_ServerStorage__add_ephemeral_keys
      (self: t_ServerStorage)
      (journalist_id: Uuid.t_Uuid)
      (keys:
          Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
            Alloc.Alloc.t_Global)
    : Prims.unit =
  Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
    "{\n let journalist_keys: &mut alloc::vec::t_Vec<\n securedrop_protocol::keys::journalist::t_JournalistOneTimeKeyBundle,\n alloc::alloc::t_Global,\n > = {\n hashbrown::map::impl_88__or_insert_with::<\n lifet..."

/// Get a random ephemeral key set for a journalist and remove it from the pool
/// Returns None if no keys are available for this journalist
/// Note: This method deletes the ephemeral key from storage.
/// The returned key is permanently removed from the journalist's ephemeral key pool.
let impl_ServerStorage__pop_random_ephemeral_keys
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_ServerStorage)
      (journalist_id: Uuid.t_Uuid)
      (rng: v_R)
    : (t_ServerStorage & v_R &
      Core_models.Option.t_Option Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle) =
  let hax_temp_output:Core_models.Option.t_Option
  Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle =
    Rust_primitives.Hax.failure "The mutation of this [1m&mut[0m is not allowed here.\n\nThis is discussed in issue https://github.com/hacspec/hax/issues/420.\nPlease upvote or comment this issue if you see this error message.\n[90mNote: the error was labeled with context `DirectAndMut`.\n[0m"
      "(match (hashbrown::map::impl_5__get_mut::<\n uuid::t_Uuid,\n alloc::vec::t_Vec<\n securedrop_protocol::keys::journalist::t_JournalistOneTimeKeyBundle,\n alloc::alloc::t_Global,\n >,\n core_models::hash::t_B..."

  in
  self, rng, hax_temp_output
  <:
  (t_ServerStorage & v_R &
    Core_models.Option.t_Option Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)

/// Get random ephemeral keys for all journalists
/// Returns a vector of (journalist_id, ephemeral_keys) pairs
/// Only includes journalists that have available keys
/// Note: This method deletes the ephemeral keys from storage.
/// Each call removes the returned keys from the journalist's ephemeral key pool.
let impl_ServerStorage__get_all_ephemeral_keys
      (#v_R: Type0)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i0: Rand_core.t_RngCore v_R)
      (#[FStar.Tactics.Typeclasses.tcresolve ()] i1: Rand_core.t_CryptoRng v_R)
      (self: t_ServerStorage)
      (rng: v_R)
    : (t_ServerStorage & v_R &
      Alloc.Vec.t_Vec
        (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
        Alloc.Alloc.t_Global) =
  let result:Alloc.Vec.t_Vec
    (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
    Alloc.Alloc.t_Global =
    Alloc.Vec.impl__new #(Uuid.t_Uuid &
        Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
      ()
  in
  let (journalist_ids: Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global):Alloc.Vec.t_Vec Uuid.t_Uuid
    Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_collect #(Core_models.Iter.Adapters.Copied.t_Copied
        (Hashbrown.Map.t_Keys Uuid.t_Uuid
            (Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
                Alloc.Alloc.t_Global)))
      #FStar.Tactics.Typeclasses.solve
      #(Alloc.Vec.t_Vec Uuid.t_Uuid Alloc.Alloc.t_Global)
      (Core_models.Iter.Traits.Iterator.f_copied #(Hashbrown.Map.t_Keys Uuid.t_Uuid
              (Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
                  Alloc.Alloc.t_Global))
          #FStar.Tactics.Typeclasses.solve
          #Uuid.t_Uuid
          (Hashbrown.Map.impl_4__keys #Uuid.t_Uuid
              #(Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
                  Alloc.Alloc.t_Global)
              #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
              #Allocator_api2.Stable.Alloc.Global.t_Global
              self.f_ephemeral_keys
            <:
            Hashbrown.Map.t_Keys Uuid.t_Uuid
              (Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
                  Alloc.Alloc.t_Global))
        <:
        Core_models.Iter.Adapters.Copied.t_Copied
        (Hashbrown.Map.t_Keys Uuid.t_Uuid
            (Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
                Alloc.Alloc.t_Global)))
  in
  let
  (result:
    Alloc.Vec.t_Vec (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
      Alloc.Alloc.t_Global),
  (rng: v_R),
  (self: t_ServerStorage) =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec
              Uuid.t_Uuid Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          journalist_ids
        <:
        Alloc.Vec.Into_iter.t_IntoIter Uuid.t_Uuid Alloc.Alloc.t_Global)
      (result, rng, self
        <:
        (Alloc.Vec.t_Vec
            (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
            Alloc.Alloc.t_Global &
          v_R &
          t_ServerStorage))
      (fun temp_0_ journalist_id ->
          let
          (result:
            Alloc.Vec.t_Vec
              (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
              Alloc.Alloc.t_Global),
          (rng: v_R),
          (self: t_ServerStorage) =
            temp_0_
          in
          let journalist_id:Uuid.t_Uuid = journalist_id in
          let
          (tmp0: t_ServerStorage),
          (tmp1: v_R),
          (out:
            Core_models.Option.t_Option
            Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle) =
            impl_ServerStorage__pop_random_ephemeral_keys #v_R self journalist_id rng
          in
          let self:t_ServerStorage = tmp0 in
          let rng:v_R = tmp1 in
          match
            out
            <:
            Core_models.Option.t_Option
            Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
          with
          | Core_models.Option.Option_Some keys ->
            let result:Alloc.Vec.t_Vec
              (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
              Alloc.Alloc.t_Global =
              Alloc.Vec.impl_1__push #(Uuid.t_Uuid &
                  Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
                #Alloc.Alloc.t_Global
                result
                (journalist_id, keys
                  <:
                  (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle))
            in
            result, rng, self
            <:
            (Alloc.Vec.t_Vec
                (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
                Alloc.Alloc.t_Global &
              v_R &
              t_ServerStorage)
          | _ ->
            result, rng, self
            <:
            (Alloc.Vec.t_Vec
                (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
                Alloc.Alloc.t_Global &
              v_R &
              t_ServerStorage))
  in
  let hax_temp_output:Alloc.Vec.t_Vec
    (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
    Alloc.Alloc.t_Global =
    result
  in
  self, rng, hax_temp_output
  <:
  (t_ServerStorage & v_R &
    Alloc.Vec.t_Vec (Uuid.t_Uuid & Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle)
      Alloc.Alloc.t_Global)

/// Check how many ephemeral keys are available for a journalist
let impl_ServerStorage__ephemeral_keys_count (self: t_ServerStorage) (journalist_id: Uuid.t_Uuid)
    : usize =
  Core_models.Option.impl__map_or #(Alloc.Vec.t_Vec
        Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle Alloc.Alloc.t_Global)
    #usize
    (Hashbrown.Map.impl_5__get #Uuid.t_Uuid
        #(Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
            Alloc.Alloc.t_Global)
        #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
        #Allocator_api2.Stable.Alloc.Global.t_Global
        #Uuid.t_Uuid
        self.f_ephemeral_keys
        journalist_id
      <:
      Core_models.Option.t_Option
      (Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
          Alloc.Alloc.t_Global))
    (mk_usize 0)
    (fun keys ->
        let keys:Alloc.Vec.t_Vec Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
          Alloc.Alloc.t_Global =
          keys
        in
        Alloc.Vec.impl_1__len #Securedrop_protocol.Keys.Journalist.t_JournalistOneTimeKeyBundle
          #Alloc.Alloc.t_Global
          keys
        <:
        usize)

/// Check if a journalist has any ephemeral keys available
let impl_ServerStorage__has_ephemeral_keys (self: t_ServerStorage) (journalist_id: Uuid.t_Uuid)
    : bool = (impl_ServerStorage__ephemeral_keys_count self journalist_id <: usize) >. mk_usize 0

/// Get all journalists
let impl_ServerStorage__get_journalists (self: t_ServerStorage)
    : Hashbrown.Map.t_HashMap Uuid.t_Uuid
      (Securedrop_protocol.Sign.t_VerifyingKey & Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
        Securedrop_protocol.Sign.t_SelfSignature &
        Securedrop_protocol.Sign.t_Signature)
      (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
      Allocator_api2.Stable.Alloc.Global.t_Global = self.f_journalists

/// Add a journalist to storage and return the generated UUID
let impl_ServerStorage__add_journalist
      (self: t_ServerStorage)
      (enrollment_bundle: Securedrop_protocol.Keys.Journalist.t_JournalistEnrollmentKeyBundle)
      (newsroom_signature: Securedrop_protocol.Sign.t_Signature)
    : (t_ServerStorage & Uuid.t_Uuid) =
  let journalist_id:Uuid.t_Uuid = Uuid.V4.impl__new_v4 () in
  let keys:(Securedrop_protocol.Sign.t_VerifyingKey &
    Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
    Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
    Securedrop_protocol.Sign.t_SelfSignature &
    Securedrop_protocol.Sign.t_Signature) =
    enrollment_bundle.Securedrop_protocol.Keys.Journalist.f_signing_key,
    enrollment_bundle.Securedrop_protocol.Keys.Journalist.f_public_keys
      .Securedrop_protocol.Keys.Journalist.f_fetch_key,
    enrollment_bundle.Securedrop_protocol.Keys.Journalist.f_public_keys
      .Securedrop_protocol.Keys.Journalist.f_reply_key,
    enrollment_bundle.Securedrop_protocol.Keys.Journalist.f_self_signature,
    newsroom_signature
    <:
    (Securedrop_protocol.Sign.t_VerifyingKey & Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
      Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
      Securedrop_protocol.Sign.t_SelfSignature &
      Securedrop_protocol.Sign.t_Signature)
  in
  let
  (tmp0:
    Hashbrown.Map.t_HashMap Uuid.t_Uuid
      (Securedrop_protocol.Sign.t_VerifyingKey & Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
        Securedrop_protocol.Sign.t_SelfSignature &
        Securedrop_protocol.Sign.t_Signature)
      (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
      Allocator_api2.Stable.Alloc.Global.t_Global),
  (out:
    Core_models.Option.t_Option
    (Securedrop_protocol.Sign.t_VerifyingKey & Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
      Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
      Securedrop_protocol.Sign.t_SelfSignature &
      Securedrop_protocol.Sign.t_Signature)) =
    Hashbrown.Map.impl_5__insert #Uuid.t_Uuid
      #(Securedrop_protocol.Sign.t_VerifyingKey &
        Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
        Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
        Securedrop_protocol.Sign.t_SelfSignature &
        Securedrop_protocol.Sign.t_Signature)
      #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
      #Allocator_api2.Stable.Alloc.Global.t_Global
      self.f_journalists
      journalist_id
      keys
  in
  let self:t_ServerStorage = { self with f_journalists = tmp0 } <: t_ServerStorage in
  let _:Core_models.Option.t_Option
  (Securedrop_protocol.Sign.t_VerifyingKey & Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
    Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
    Securedrop_protocol.Sign.t_SelfSignature &
    Securedrop_protocol.Sign.t_Signature) =
    out
  in
  let hax_temp_output:Uuid.t_Uuid = journalist_id in
  self, hax_temp_output <: (t_ServerStorage & Uuid.t_Uuid)

/// Find a journalist by their verifying key
/// Returns the journalist ID if found
/// TODO: Remove?
let impl_ServerStorage__find_journalist_by_verifying_key
      (self: t_ServerStorage)
      (verifying_key: Securedrop_protocol.Sign.t_VerifyingKey)
    : Core_models.Option.t_Option Uuid.t_Uuid =
  match
    Rust_primitives.Hax.Folds.fold_return (Core_models.Iter.Traits.Collect.f_into_iter #(Hashbrown.Map.t_HashMap
              Uuid.t_Uuid
              (Securedrop_protocol.Sign.t_VerifyingKey &
                Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
                Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
                Securedrop_protocol.Sign.t_SelfSignature &
                Securedrop_protocol.Sign.t_Signature)
              (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
              Allocator_api2.Stable.Alloc.Global.t_Global)
          #FStar.Tactics.Typeclasses.solve
          self.f_journalists
        <:
        Hashbrown.Map.t_Iter Uuid.t_Uuid
          (Securedrop_protocol.Sign.t_VerifyingKey &
            Securedrop_protocol.Primitives.X25519.t_DHPublicKey &
            Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey &
            Securedrop_protocol.Sign.t_SelfSignature &
            Securedrop_protocol.Sign.t_Signature))
      ()
      (fun temp_0_ temp_1_ ->
          let _:Prims.unit = temp_0_ in
          let
          (journalist_id: Uuid.t_Uuid),
          ((stored_vk: Securedrop_protocol.Sign.t_VerifyingKey),
            (_: Securedrop_protocol.Primitives.X25519.t_DHPublicKey),
            (_: Securedrop_protocol.Primitives.Dh_akem.t_DhAkemPublicKey),
            (_: Securedrop_protocol.Sign.t_SelfSignature),
            (_: Securedrop_protocol.Sign.t_Signature)) =
            temp_1_
          in
          if
            (Securedrop_protocol.Sign.impl_VerifyingKey__into_bytes stored_vk
              <:
              t_Array u8 (mk_usize 32)) =.
            (Securedrop_protocol.Sign.impl_VerifyingKey__into_bytes verifying_key
              <:
              t_Array u8 (mk_usize 32))
            <:
            bool
          then
            Core_models.Ops.Control_flow.ControlFlow_Break
            (Core_models.Ops.Control_flow.ControlFlow_Break
              (Core_models.Option.Option_Some journalist_id
                <:
                Core_models.Option.t_Option Uuid.t_Uuid)
              <:
              Core_models.Ops.Control_flow.t_ControlFlow (Core_models.Option.t_Option Uuid.t_Uuid)
                (Prims.unit & Prims.unit))
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Core_models.Ops.Control_flow.t_ControlFlow (Core_models.Option.t_Option Uuid.t_Uuid)
                  (Prims.unit & Prims.unit)) Prims.unit
          else
            Core_models.Ops.Control_flow.ControlFlow_Continue ()
            <:
            Core_models.Ops.Control_flow.t_ControlFlow
              (Core_models.Ops.Control_flow.t_ControlFlow (Core_models.Option.t_Option Uuid.t_Uuid)
                  (Prims.unit & Prims.unit)) Prims.unit)
    <:
    Core_models.Ops.Control_flow.t_ControlFlow (Core_models.Option.t_Option Uuid.t_Uuid) Prims.unit
  with
  | Core_models.Ops.Control_flow.ControlFlow_Break ret -> ret
  | Core_models.Ops.Control_flow.ControlFlow_Continue _ ->
    Core_models.Option.Option_None <: Core_models.Option.t_Option Uuid.t_Uuid

/// Get all messages
let impl_ServerStorage__get_messages (self: t_ServerStorage)
    : Hashbrown.Map.t_HashMap Uuid.t_Uuid
      Securedrop_protocol.Messages.Core.t_Message
      (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
      Allocator_api2.Stable.Alloc.Global.t_Global = self.f_messages

/// Add a message to storage
let impl_ServerStorage__add_message
      (self: t_ServerStorage)
      (message_id: Uuid.t_Uuid)
      (message: Securedrop_protocol.Messages.Core.t_Message)
    : t_ServerStorage =
  let
  (tmp0:
    Hashbrown.Map.t_HashMap Uuid.t_Uuid
      Securedrop_protocol.Messages.Core.t_Message
      (Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
      Allocator_api2.Stable.Alloc.Global.t_Global),
  (out: Core_models.Option.t_Option Securedrop_protocol.Messages.Core.t_Message) =
    Hashbrown.Map.impl_5__insert #Uuid.t_Uuid
      #Securedrop_protocol.Messages.Core.t_Message
      #(Core_models.Hash.t_BuildHasherDefault Ahash.Fallback_hash.t_AHasher)
      #Allocator_api2.Stable.Alloc.Global.t_Global
      self.f_messages
      message_id
      message
  in
  let self:t_ServerStorage = { self with f_messages = tmp0 } <: t_ServerStorage in
  let _:Core_models.Option.t_Option Securedrop_protocol.Messages.Core.t_Message = out in
  self
