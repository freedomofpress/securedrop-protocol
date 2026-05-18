module Libcrux_ml_kem.Ind_cpa
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Libcrux_ml_kem.Hash_functions in
  let open Libcrux_ml_kem.Ind_cpa.Unpacked in
  let open Libcrux_ml_kem.Variant in
  let open Libcrux_ml_kem.Vector.Traits in
  ()

/// Call [`serialize_uncompressed_ring_element`] for each ring element.
val serialize_vector
      (v_K: usize)
      (#v_Vector: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      (key: t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K)
      (out: t_Slice u8)
    : Prims.Pure (t_Slice u8)
      (requires
        Spec.MLKEM.is_rank v_K /\
        Core_models.Slice.impl__len #u8 out == Spec.MLKEM.v_RANKED_BYTES_PER_RING_ELEMENT v_K /\
        (forall (i: nat).
            i < v v_K ==> Libcrux_ml_kem.Polynomial.is_bounded_poly 3328 (Seq.index key i)))
      (ensures
        fun out_future ->
          let out_future:t_Slice u8 = out_future in
          out ==
          Spec.MLKEM.vector_encode_12 #v_K
            (Libcrux_ml_kem.Polynomial.to_spec_vector_t #v_K #v_Vector key))

/// Concatenate `t` and `ρ` into the public key.
val serialize_public_key_mut
      (v_K v_PUBLIC_KEY_SIZE: usize)
      (#v_Vector: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      (tt_as_ntt: t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K)
      (seed_for_a: t_Slice u8)
      (serialized: t_Array u8 v_PUBLIC_KEY_SIZE)
    : Prims.Pure (t_Array u8 v_PUBLIC_KEY_SIZE)
      (requires
        Spec.MLKEM.is_rank v_K /\ v_PUBLIC_KEY_SIZE == Spec.MLKEM.v_CPA_PUBLIC_KEY_SIZE v_K /\
        length seed_for_a == sz 32 /\
        (forall (i: nat).
            i < v v_K ==> Libcrux_ml_kem.Polynomial.is_bounded_poly 3328 (Seq.index tt_as_ntt i)))
      (ensures
        fun serialized_future ->
          let serialized_future:t_Array u8 v_PUBLIC_KEY_SIZE = serialized_future in
          serialized_future ==
          Seq.append (Spec.MLKEM.vector_encode_12 #v_K
                (Libcrux_ml_kem.Polynomial.to_spec_vector_t #v_K #v_Vector tt_as_ntt))
            seed_for_a)

/// Concatenate `t` and `ρ` into the public key.
val serialize_public_key
      (v_K v_PUBLIC_KEY_SIZE: usize)
      (#v_Vector: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      (tt_as_ntt: t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K)
      (seed_for_a: t_Slice u8)
    : Prims.Pure (t_Array u8 v_PUBLIC_KEY_SIZE)
      (requires
        Spec.MLKEM.is_rank v_K /\ v_PUBLIC_KEY_SIZE == Spec.MLKEM.v_CPA_PUBLIC_KEY_SIZE v_K /\
        length seed_for_a == sz 32 /\
        (forall (i: nat).
            i < v v_K ==> Libcrux_ml_kem.Polynomial.is_bounded_poly 3328 (Seq.index tt_as_ntt i)))
      (ensures
        fun res ->
          let res:t_Array u8 v_PUBLIC_KEY_SIZE = res in
          res ==
          Seq.append (Spec.MLKEM.vector_encode_12 #v_K
                (Libcrux_ml_kem.Polynomial.to_spec_vector_t #v_K #v_Vector tt_as_ntt))
            seed_for_a)

/// Sample a vector of ring elements from a centered binomial distribution and
/// convert them into their NTT representations.
val sample_vector_cbd_then_ntt
      (v_K v_ETA v_ETA_RANDOMNESS_SIZE: usize)
      (#v_Vector #v_Hasher: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      {| i1: Libcrux_ml_kem.Hash_functions.t_Hash v_Hasher v_K |}
      (re_as_ntt: t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K)
      (prf_input: t_Array u8 (mk_usize 33))
      (domain_separator: u8)
    : Prims.Pure (t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K & u8)
      (requires
        Spec.MLKEM.is_rank v_K /\ v_ETA_RANDOMNESS_SIZE == Spec.MLKEM.v_ETA1_RANDOMNESS_SIZE v_K /\
        v_ETA == Spec.MLKEM.v_ETA1 v_K /\ v domain_separator < 2 * v v_K /\
        range (v domain_separator + v v_K) u8_inttype)
      (ensures
        fun temp_0_ ->
          let
          (re_as_ntt_future:
            t_Array (Libcrux_ml_kem.Polynomial.t_PolynomialRingElement v_Vector) v_K),
          (ds: u8) =
            temp_0_
          in
          v ds == v domain_separator + v v_K /\
          Libcrux_ml_kem.Polynomial.to_spec_vector_t #v_K #v_Vector re_as_ntt_future ==
          Spec.MLKEM.sample_vector_cbd_then_ntt #v_K
            (Seq.slice prf_input 0 32)
            (sz (v domain_separator)) /\
          (forall (i: nat).
              i < v v_K ==>
              Libcrux_ml_kem.Polynomial.is_bounded_poly #v_Vector
                3328
                (Seq.index re_as_ntt_future i)))

/// This function implements most of <strong>Algorithm 12</strong> of the
/// NIST FIPS 203 specification; this is the Kyber CPA-PKE key generation algorithm.
/// We say \"most of\" since Algorithm 12 samples the required randomness within
/// the function itself, whereas this implementation expects it to be provided
/// through the `key_generation_seed` parameter.
/// Algorithm 12 is reproduced below:
/// ```plaintext
/// Output: encryption key ekₚₖₑ ∈ 𝔹^{384k+32}.
/// Output: decryption key dkₚₖₑ ∈ 𝔹^{384k}.
/// d ←$ B
/// (ρ,σ) ← G(d)
/// N ← 0
/// for (i ← 0; i < k; i++)
///     for(j ← 0; j < k; j++)
///         Â[i,j] ← SampleNTT(XOF(ρ, i, j))
///     end for
/// end for
/// for(i ← 0; i < k; i++)
///     s[i] ← SamplePolyCBD_{η₁}(PRF_{η₁}(σ,N))
///     N ← N + 1
/// end for
/// for(i ← 0; i < k; i++)
///     e[i] ← SamplePolyCBD_{η₂}(PRF_{η₂}(σ,N))
///     N ← N + 1
/// end for
/// ŝ ← NTT(s)
/// ê ← NTT(e)
/// t\u{302} ← Â◦ŝ + ê
/// ekₚₖₑ ← ByteEncode₁₂(t\u{302}) ‖ ρ
/// dkₚₖₑ ← ByteEncode₁₂(ŝ)
/// ```
/// The NIST FIPS 203 standard can be found at
/// <https://csrc.nist.gov/pubs/fips/203/ipd>.
val generate_keypair_unpacked
      (v_K v_ETA1 v_ETA1_RANDOMNESS_SIZE: usize)
      (#v_Vector #v_Hasher #v_Scheme: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      {| i1: Libcrux_ml_kem.Hash_functions.t_Hash v_Hasher v_K |}
      {| i2: Libcrux_ml_kem.Variant.t_Variant v_Scheme |}
      (key_generation_seed: t_Slice u8)
      (private_key: Libcrux_ml_kem.Ind_cpa.Unpacked.t_IndCpaPrivateKeyUnpacked v_K v_Vector)
      (public_key: Libcrux_ml_kem.Ind_cpa.Unpacked.t_IndCpaPublicKeyUnpacked v_K v_Vector)
    : Prims.Pure
      (Libcrux_ml_kem.Ind_cpa.Unpacked.t_IndCpaPrivateKeyUnpacked v_K v_Vector &
        Libcrux_ml_kem.Ind_cpa.Unpacked.t_IndCpaPublicKeyUnpacked v_K v_Vector)
      (requires
        Spec.MLKEM.is_rank v_K /\ v_ETA1_RANDOMNESS_SIZE == Spec.MLKEM.v_ETA1_RANDOMNESS_SIZE v_K /\
        v_ETA1 == Spec.MLKEM.v_ETA1 v_K /\
        length key_generation_seed == Spec.MLKEM.v_CPA_KEY_GENERATION_SEED_SIZE)
      (ensures
        fun temp_0_ ->
          let
          (private_key_future:
            Libcrux_ml_kem.Ind_cpa.Unpacked.t_IndCpaPrivateKeyUnpacked v_K v_Vector),
          (public_key_future:
            Libcrux_ml_kem.Ind_cpa.Unpacked.t_IndCpaPublicKeyUnpacked v_K v_Vector) =
            temp_0_
          in
          let public_key_future:Libcrux_ml_kem.Ind_cpa.Unpacked.t_IndCpaPublicKeyUnpacked v_K
            v_Vector =
            public_key_future
          in
          let (((t_as_ntt, seed_for_A), matrix_A_as_ntt), secret_as_ntt), valid =
            Spec.MLKEM.ind_cpa_generate_keypair_unpacked v_K key_generation_seed
          in
          (valid ==>
            (Libcrux_ml_kem.Polynomial.to_spec_vector_t #v_K
                #v_Vector
                public_key_future.Libcrux_ml_kem.Ind_cpa.Unpacked.f_tt_as_ntt ==
              t_as_ntt) /\ (public_key_future.f_seed_for_A == seed_for_A) /\
            (Libcrux_ml_kem.Polynomial.to_spec_matrix_t #v_K #v_Vector public_key_future.f_A ==
              matrix_A_as_ntt) /\
            (Libcrux_ml_kem.Polynomial.to_spec_vector_t #v_K
                #v_Vector
                private_key_future.f_secret_as_ntt ==
              secret_as_ntt)) /\
          (forall (i: nat).
              i < v v_K ==>
              Libcrux_ml_kem.Polynomial.is_bounded_poly 3328
                (Seq.index private_key_future.f_secret_as_ntt i)) /\
          (forall (i: nat).
              i < v v_K ==>
              Libcrux_ml_kem.Polynomial.is_bounded_poly 3328
                (Seq.index public_key_future.Libcrux_ml_kem.Ind_cpa.Unpacked.f_tt_as_ntt i)))

/// Serialize the secret key from the unpacked key pair generation.
val serialize_unpacked_secret_key
      (v_K v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE: usize)
      (#v_Vector: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      (public_key: Libcrux_ml_kem.Ind_cpa.Unpacked.t_IndCpaPublicKeyUnpacked v_K v_Vector)
      (private_key: Libcrux_ml_kem.Ind_cpa.Unpacked.t_IndCpaPrivateKeyUnpacked v_K v_Vector)
    : Prims.Pure (t_Array u8 v_PRIVATE_KEY_SIZE & t_Array u8 v_PUBLIC_KEY_SIZE)
      Prims.l_True
      (fun _ -> Prims.l_True)

val generate_keypair
      (v_K v_PRIVATE_KEY_SIZE v_PUBLIC_KEY_SIZE v_ETA1 v_ETA1_RANDOMNESS_SIZE: usize)
      (#v_Vector #v_Hasher #v_Scheme: Type0)
      {| i0: Libcrux_ml_kem.Vector.Traits.t_Operations v_Vector |}
      {| i1: Libcrux_ml_kem.Hash_functions.t_Hash v_Hasher v_K |}
      {| i2: Libcrux_ml_kem.Variant.t_Variant v_Scheme |}
      (key_generation_seed: t_Slice u8)
    : Prims.Pure (t_Array u8 v_PRIVATE_KEY_SIZE & t_Array u8 v_PUBLIC_KEY_SIZE)
      (requires
        Spec.MLKEM.is_rank v_K /\ v_PRIVATE_KEY_SIZE == Spec.MLKEM.v_CPA_PRIVATE_KEY_SIZE v_K /\
        v_PUBLIC_KEY_SIZE == Spec.MLKEM.v_CPA_PUBLIC_KEY_SIZE v_K /\ v_ETA1 == Spec.MLKEM.v_ETA1 v_K /\
        v_ETA1_RANDOMNESS_SIZE == Spec.MLKEM.v_ETA1_RANDOMNESS_SIZE v_K /\
        length key_generation_seed == Spec.MLKEM.v_CPA_KEY_GENERATION_SEED_SIZE)
      (ensures
        fun result ->
          let result:(t_Array u8 v_PRIVATE_KEY_SIZE & t_Array u8 v_PUBLIC_KEY_SIZE) = result in
          let expected, valid = Spec.MLKEM.ind_cpa_generate_keypair v_K key_generation_seed in
          valid ==> result == expected)
