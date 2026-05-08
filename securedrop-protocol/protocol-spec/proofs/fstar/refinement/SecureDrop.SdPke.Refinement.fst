module SecureDrop.SdPke.Refinement

(* ============================================================================
   Refinement of `Securedrop_protocol_minimal.Metadata` against
   `Securedrop_protocol_spec.Sd_pke`.

   STATUS: DRAFT.

   The names below match the impl-side extraction at
   `protocol-minimal/proofs/fstar/extraction/Securedrop_protocol_minimal.Metadata.fst`,
   which already exists. The spec-side names (`Securedrop_protocol_spec.*`)
   are predicted; this file will not check until the spec crate is
   extracted via hax and added to the F* search path. The shape is
   chosen to require minimal manual fixup once that extraction lands.

   Lemma bodies are `admit ()`; the structure is the contract.
   ============================================================================ *)

#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"

open FStar.Mul
open Core_models

module Spec      = Securedrop_protocol_spec.Sd_pke
module SpecPrim  = Securedrop_protocol_spec.Primitives
module Impl      = Securedrop_protocol_minimal.Metadata
module ImplXwing = Securedrop_protocol_minimal.Primitives.Xwing
module HpkeRs    = Hpke_rs

(* ============================================================================
   §1. Type translations.

   Impl-side `t_MetadataPublicKey` wraps `t_XWingPublicKey` which wraps
   `t_Array u8 1216`. The spec-side `t_SdPkePk` (predicted) wraps the same
   1216-byte array directly, one newtype shallower.
   ============================================================================ *)

let pk_impl_to_spec (pk: Impl.t_MetadataPublicKey) : Spec.t_SdPkePk =
  let MetadataPublicKey xpk = pk in
  let XWingPublicKey bytes = xpk in
  Spec.SdPkePk bytes

let sk_impl_to_spec (sk: Impl.t_MetadataPrivateKey) : Spec.t_SdPkeSk =
  let MetadataPrivateKey xsk = sk in
  let XWingPrivateKey bytes = xsk in
  Spec.SdPkeSk bytes

(* The two ciphertext records are field-compatible:
   impl `{ f_c: t_Array u8 1120; f_cp: Vec u8 }`
   spec `{ f_c: t_Array u8 1120; f_cp: Vec u8 }` *)
let ct_impl_to_spec (ct: Impl.t_MetadataCiphertext) : Spec.t_SdPkeCt =
  { f_c = ct.f_c; f_cp = ct.f_cp }

(* Project `Result T anyhow::Error` to `Option T` for refinement:
   spec returns Option, impl returns Result-with-string-error. *)
let result_to_option
    (#t: Type0) (#e: Type0)
    (r: Core_models.Result.t_Result t e)
  : Core_models.Option.t_Option t
  = match r with
    | Core_models.Result.Result_Ok x   -> Core_models.Option.Option_Some x
    | Core_models.Result.Result_Err _  -> Core_models.Option.Option_None

(* ============================================================================
   §2. The HPKE refinement axiom.

   Both crates ultimately call out to HPKE-rs. The spec calls
   `SpecPrim.hpke_seal_base` (an opaque function); the impl calls
   `HpkeRs.impl_7__seal` in Mode_Base (also opaque, in the model file
   `protocol-minimal/proofs/fstar/models/Hpke_rs.fsti`).

   The axiom below states that, on Base mode with empty info/aad and no
   PSK/auth, the two opaque functions agree modulo:
     - representation of the X-Wing pubkey (raw bytes vs HpkePublicKey wrapper)
     - representation of the encapsulation output (Vec<u8> vs [u8; 1120])
     - randomness threading: the impl's HPKE state carries randomness,
       which the spec receives as an explicit argument

   This is a refinement claim about libcrux's HPKE implementation. It
   would be discharged by Cryspen's HPKE proofs against RFC 9180; we
   import it as an assumption here.
   ============================================================================ *)

(* The randomness encoded in an Hpke-rs state. Existential-style: there
   exists some `r` such that calling seal advances the state by drawing r. *)
assume
val hpke_state_randomness:
    #crypto: Type0
  → state: HpkeRs.t_Hpke crypto
  → SpecPrim.t_Array u8 96   (* the bytes the next seal call will consume *)

(* Lifting an X-Wing pubkey-bytes to the HpkePublicKey wrapper.
   In the impl extraction this is `Core_models.Convert.f_into` against
   the typeclass instance `impl_3` defined in the X-Wing extraction. *)
assume
val xwing_pk_to_hpke:
    SpecPrim.t_Array u8 1216 → HpkeRs.t_HpkePublicKey

assume
val xwing_sk_to_hpke:
    SpecPrim.t_Array u8 32 → HpkeRs.t_HpkePrivateKey

(* The core axiom: HPKE Base seal in the impl agrees with the spec. *)
assume
val hpke_seal_base_refines:
    pk_bytes: SpecPrim.t_Array u8 1216
  → m: Core_models.Slice.t_Slice u8
  → state_in: HpkeRs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux
  → Lemma
      (ensures (
        let r = hpke_state_randomness state_in in
        let (_, impl_out) =
          HpkeRs.impl_7__seal #Hpke_rs_libcrux.t_HpkeLibcrux
            state_in
            (xwing_pk_to_hpke pk_bytes)
            Core_models.Slice.empty
            Core_models.Slice.empty
            m
            Core_models.Option.Option_None
            Core_models.Option.Option_None
            Core_models.Option.Option_None
        in
        let (c_spec, cp_spec) =
          SpecPrim.hpke_seal_base pk_bytes
            Core_models.Slice.empty Core_models.Slice.empty m r
        in
        match impl_out with
        | Core_models.Result.Result_Ok (c_vec, cp_vec) ->
            (* impl produces Vec; spec produces fixed-size array. They agree
               under try_into. *)
            cp_vec == cp_spec
            /\ (Core_models.Convert.f_try_into c_vec ==
                Core_models.Result.Result_Ok c_spec)
        | Core_models.Result.Result_Err _ -> False
            (* Base mode with valid X-Wing pubkey never errors. *)
      ))

(* Symmetric axiom for HPKE Open. *)
assume
val hpke_open_base_refines:
    sk_bytes: SpecPrim.t_Array u8 32
  → c: SpecPrim.t_Array u8 1120
  → cp: Core_models.Slice.t_Slice u8
  → state_in: HpkeRs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux
  → Lemma
      (ensures (
        let impl_out =
          HpkeRs.impl_7__open #Hpke_rs_libcrux.t_HpkeLibcrux
            state_in
            (c <: Core_models.Slice.t_Slice u8)
            (xwing_sk_to_hpke sk_bytes)
            Core_models.Slice.empty
            Core_models.Slice.empty
            cp
            Core_models.Option.Option_None
            Core_models.Option.Option_None
            Core_models.Option.Option_None
        in
        let spec_out =
          SpecPrim.hpke_open_base sk_bytes c
            Core_models.Slice.empty Core_models.Slice.empty cp
        in
        result_to_option impl_out == spec_out
      ))

(* ============================================================================
   §3. Refinement lemmas for `Sd_pke.enc` / `Sd_pke.dec`.

   Each lemma reduces to applying the corresponding HPKE axiom plus
   pushing the `MetadataPublicKey` / `MetadataCiphertext` newtype
   wrappers through the equality. The bodies should be discharged by
   `hpke_seal_base_refines` / `hpke_open_base_refines` plus reflexivity.
   ============================================================================ *)

(* `Impl.encrypt` does not take randomness as an argument: it constructs
   a fresh `Hpke` state internally on every call (see lines 152-158 of
   the impl extraction). Refinement therefore quantifies over the
   randomness that this implicit state will draw.

   Concretely: for any randomness `r` that the impl's HPKE state could
   yield, calling `Impl.encrypt pk_r m` agrees with `Spec.enc (pk pk_r) m r`. *)
val enc_refines:
    pk_r: Impl.t_MetadataPublicKey
  → m: Core_models.Slice.t_Slice u8
  → r: SpecPrim.t_Array u8 96
  → Lemma
      (requires (
        (* The lemma is parameterised on the randomness the freshly
           constructed Hpke state will consume. We pin that here. *)
        forall (state: HpkeRs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux).
            hpke_state_randomness state == r
      ))
      (ensures (
        ct_impl_to_spec (Impl.encrypt pk_r m)
        == Spec.enc (pk_impl_to_spec pk_r) m r
      ))
let enc_refines pk_r m r =
  (* Proof outline:
     1. Unfold `Impl.encrypt`: it constructs `hpke = Hpke::new(Base, ...)`,
        then calls `hpke.seal(pk_r_hpke, b"", b"", m, None, None, None)`,
        unwraps the Result with `.expect(...)`, and packages `(c, cp)`.
     2. Unfold `Spec.enc`: it calls `hpke_seal_base(pk_r.0, [], [], m, r)`
        and packages `(c, cp)`.
     3. By `hpke_seal_base_refines` applied to the Hpke state used by the
        impl, the underlying seal calls produce equal `(c, cp)`.
     4. Conclude by reflexivity on the wrapping. *)
  admit ()

val dec_refines:
    sk_r: Impl.t_MetadataPrivateKey
  → ct: Impl.t_MetadataCiphertext
  → Lemma
      (ensures (
        result_to_option (Impl.decrypt sk_r ct)
        == Spec.dec (sk_impl_to_spec sk_r) (ct_impl_to_spec ct)
      ))
let dec_refines sk_r ct =
  (* Proof outline:
     1. Unfold `Impl.decrypt`: constructs Hpke state, calls
        `hpke.open(...)`, maps the error via `anyhow::anyhow!(...)`.
     2. Unfold `Spec.dec`: calls `hpke_open_base(sk_r.0, ct.f_c, [], [], ct.f_cp)`.
     3. By `hpke_open_base_refines`, the underlying calls agree under
        `result_to_option`.
     4. The error-message construction in the impl is irrelevant once
        projected through `result_to_option`. *)
  admit ()

(* ============================================================================
   §4. Round-trip correctness, derivable from §3 plus HPKE Base correctness.

   This is what the existing `proptest!` round-trip in
   `metadata.rs::tests::test_metadata_encrypt_decrypt_roundtrip` checks
   probabilistically. The lemma below states it as a theorem, given the
   HPKE-Base correctness assumption.
   ============================================================================ *)

assume
val hpke_base_correct:
    pk: SpecPrim.t_Array u8 1216
  → sk: SpecPrim.t_Array u8 32
  → m: Core_models.Slice.t_Slice u8
  → r: SpecPrim.t_Array u8 96
  → Lemma
      (requires SpecPrim.is_xwing_keypair sk pk)
      (ensures (
        let (c, cp) = SpecPrim.hpke_seal_base pk
                        Core_models.Slice.empty Core_models.Slice.empty m r in
        SpecPrim.hpke_open_base sk c
          Core_models.Slice.empty Core_models.Slice.empty cp
        == Core_models.Option.Option_Some
             (Alloc.Slice.impl__to_vec #u8 m)
      ))

val roundtrip_refines:
    sk_r: Impl.t_MetadataPrivateKey
  → pk_r: Impl.t_MetadataPublicKey
  → m: Core_models.Slice.t_Slice u8
  → r: SpecPrim.t_Array u8 96
  → Lemma
      (requires (
        (* (sk_r, pk_r) is a valid X-Wing keypair *)
        SpecPrim.is_xwing_keypair (sk_impl_to_spec sk_r)._0
                                  (pk_impl_to_spec pk_r)._0
        /\ (forall (state: HpkeRs.t_Hpke Hpke_rs_libcrux.t_HpkeLibcrux).
              hpke_state_randomness state == r)
      ))
      (ensures (
        result_to_option (Impl.decrypt sk_r (Impl.encrypt pk_r m))
        == Core_models.Option.Option_Some
             (Alloc.Slice.impl__to_vec #u8 m)
      ))
let roundtrip_refines sk_r pk_r m r =
  enc_refines pk_r m r;
  dec_refines sk_r (Impl.encrypt pk_r m);
  hpke_base_correct (pk_impl_to_spec pk_r)._0
                    (sk_impl_to_spec sk_r)._0
                    m r
