module Securedrop_protocol_minimal.Primitives.Pad
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Fixed-length padded message length.
/// Note: I made this up. We should pick something based on actual reasons.
let v_PADDED_MESSAGE_LEN: usize = mk_usize 100000

/// Pad a message to a fixed length.
/// # Panics
/// Panics if `message` is longer than `PADDED_MESSAGE_LEN`. The verification
/// precondition (`requires`) rules this out, so the panic is provably
/// unreachable and the length subtraction is safe.
let pad_message (message: t_Slice u8)
    : Prims.Pure (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
      (requires (Core_models.Slice.impl__len #u8 message <: usize) <=. v_PADDED_MESSAGE_LEN)
      (fun _ -> Prims.l_True) =
  let _:Prims.unit =
    if (Core_models.Slice.impl__len #u8 message <: usize) >. v_PADDED_MESSAGE_LEN
    then
      Rust_primitives.Hax.never_to_any (Core_models.Panicking.panic_fmt (Core_models.Fmt.Rt.impl_1__new_const
                (mk_usize 1)
                (let list = ["Message too long for padding"] in
                  FStar.Pervasives.assert_norm (Prims.eq2 (List.Tot.length list) 1);
                  Rust_primitives.Hax.array_of_list 1 list)
              <:
              Core_models.Fmt.t_Arguments)
          <:
          Rust_primitives.Hax.t_Never)
  in
  let padded:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl__with_capacity #u8 v_PADDED_MESSAGE_LEN
  in
  let padded:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8 #Alloc.Alloc.t_Global padded message
  in
  let padding:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.from_elem #u8
      (mk_u8 0)
      (v_PADDED_MESSAGE_LEN -! (Core_models.Slice.impl__len #u8 message <: usize) <: usize)
  in
  let padded:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
    Alloc.Vec.impl_2__extend_from_slice #u8
      #Alloc.Alloc.t_Global
      padded
      (Alloc.Vec.impl_1__as_slice padding <: t_Slice u8)
  in
  padded
