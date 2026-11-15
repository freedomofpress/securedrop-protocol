-- [securedrop_protocol_minimal]: external types.
-- Seeded by hax from Extraction/TypesExternal_Template.lean: fill the holes.
-- hax never modifies this file; after re-extraction, compare it against the
-- regenerated template to see what changed.
module
public import Aeneas
public import CoreModels
@[expose] public section
open CoreModels Aeneas
open Aeneas.Std hiding namespace core alloc
open RustM ControlFlow Error
open Std.Do
set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option linter.style.whitespace false
set_option linter.style.setOption false
set_option linter.style.longLine false
set_option linter.internalConstructors false

/- You can set the `maxHeartbeats` value with the `-max-heartbeats` CLI option -/
set_option maxHeartbeats 1000000

/- You can set the `maxRecDepth` value with the `-max-recdepth` CLI option -/
set_option maxRecDepth 2048

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::Point]
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 45:4-45:44 -/
axiom primitives.provider.ristretto255.Point : Type

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::Scalar]
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 50:4-50:42 -/
axiom primitives.provider.ristretto255.Scalar : Type

