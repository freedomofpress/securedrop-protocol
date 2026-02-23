module Libcrux_kem

open Rust_primitives

val t_PrivateKey : Type0
val t_PublicKey : Type0
val impl_PrivateKey__encode : t_PrivateKey -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
val impl_PublicKey__encode  : t_PublicKey  -> Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global
