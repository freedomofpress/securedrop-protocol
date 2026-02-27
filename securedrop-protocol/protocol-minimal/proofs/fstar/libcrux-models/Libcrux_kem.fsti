// libcrux-kem is currently "pre-verification"[^1], so for now we must provide
// stubs for properties we want to prove on top of libcrux *assuming* that it
// provides them.
//
// [^1]: https://github.com/cryspen/libcrux/blob/3ade18381ad3144d755507f97994933d8585839b/Readme.md?plain=1#L31-L33

module Libcrux_kem

open Rust_primitives

val t_PrivateKey : Type0
val t_PublicKey : Type0
val impl_PrivateKey__encode : t_PrivateKey ->
  v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global { Seq.length v = 32 }
val impl_PublicKey__encode  : t_PublicKey  ->
  v: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global { Seq.length v = 1216 }
