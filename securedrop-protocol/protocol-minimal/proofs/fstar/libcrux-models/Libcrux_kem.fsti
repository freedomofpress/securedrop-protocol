module Libcrux_kem

open Rust_primitives

val t_PrivateKey : Type0
val t_PublicKey : Type0
val impl_PrivateKey__encode : t_PrivateKey ->
  v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global { Seq.length v = 32 }
val impl_PublicKey__encode  : t_PublicKey  ->
  v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global { Seq.length v = 1216 }
