module Securedrop_protocol_minimal.Sealed
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

/// Use [sealed trait pattern](https://rust-lang.github.io/api-guidelines/future-proofing.html#c-sealed)
/// to gate features that downstream crates should not implement.
/// This module should never be exposed publicly or re-exported (i.e., no `pub use::sealed::*`)!
/// To use, define a public trait (eg in traits.rs):
/// ``` use crate::sealed; ```
/// ``` pub trait RestrictedTrait: sealed::Sealed {}` ```
/// The `Sealed` trait is public as long as UserSecret, RestrictedApi, etc are public;
/// if those ever become pub(crate) then this trait can be restricted as well.
class t_Sealed (v_Self: Type0) = { __marker_trait_t_Sealed:Prims.unit }
