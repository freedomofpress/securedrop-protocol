-- [securedrop_protocol_minimal]: external functions.
-- Seeded by hax from Extraction/FunsExternal_Template.lean: fill the holes.
-- hax never modifies this file; after re-extraction, compare it against the
-- regenerated template to see what changed.
module
public import Aeneas
public import CoreModels
public import SecuredropProtocolMinimal.Extraction.Types
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
open securedrop_protocol_minimal

/-- [securedrop_protocol_minimal::client::challenge::solve_fetch_challenges]:
    Source: 'protocol-minimal/src/client/challenge.rs', lines 11:0-37:1
    Visibility: public -/
axiom client.challenge.solve_fetch_challenges
  {S : Type _} (traitsUserSecretInst : traits.UserSecret S) :
  S → Slice wire.core.FetchResponse → RustM (alloc.vec.Vec uuid.Uuid)

/-- [securedrop_protocol_minimal::schemes::message::auth_enc]:
    Source: 'protocol-minimal/src/schemes/message.rs', lines 270:0-327:1
    Visibility: public -/
axiom schemes.message.auth_enc
  {R : Type _} {Clause1_Clause1_Clause0_Error : Type _} (rand_coreRngCoreInst :
  rand_core.RngCore R) (rand_coreCryptoRngInst : rand_core.CryptoRng R
  Clause1_Clause1_Clause0_Error) :
  R → schemes.message.MessageKeyPair → schemes.message.MessagePublicKey →
    Slice Std.U8 → Slice Std.U8 → primitives.ristretto255.DHPublicKey →
    RustM ((core.result.Result schemes.message.MessageCiphertext anyhow.Error)
    × R)

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::dh]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 111:4-113:5 -/
axiom primitives.provider.ristretto255.dh
  :
  primitives.provider.ristretto255.Point →
    primitives.provider.ristretto255.Scalar → RustM
    primitives.provider.ristretto255.Point

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::secret_to_public]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 105:4-107:5 -/
axiom primitives.provider.ristretto255.secret_to_public
  :
  primitives.provider.ristretto255.Scalar → RustM
    primitives.provider.ristretto255.Point

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::scalar_from_wide]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 59:4-61:5 -/
axiom primitives.provider.ristretto255.scalar_from_wide
  : Array Std.U8 64#usize → RustM primitives.provider.ristretto255.Scalar

/-- [securedrop_protocol_minimal::primitives::provider::rng::fill_bytes]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 156:4-161:5 -/
axiom primitives.provider.rng.fill_bytes
  {R : Type _} {Clause1_Clause1_Clause0_Error : Type _} {N : Std.Usize}
  (rand_coreRngCoreInst : rand_core.RngCore R) (rand_coreCryptoRngInst :
  rand_core.CryptoRng R Clause1_Clause1_Clause0_Error) :
  R → Array Std.U8 N → RustM (R × (Array Std.U8 N))

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::encode]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 99:4-101:5 -/
axiom primitives.provider.ristretto255.encode
  : primitives.provider.ristretto255.Point → RustM (Array Std.U8 32#usize)

/-- [securedrop_protocol_minimal::client::message::decrypt]:
    Source: 'protocol-minimal/src/client/message.rs', lines 70:0-72:1
    Visibility: public -/
axiom client.message.decrypt
  {U : Type _} (traitsUserSecretInst : traits.UserSecret U) :
  U → wire.core.Envelope → RustM client.plaintext.Plaintext

/-- [securedrop_protocol_minimal::client::message::decrypt_with_sender]:
    Source: 'protocol-minimal/src/client/message.rs', lines 77:0-111:1
    Visibility: public -/
axiom client.message.decrypt_with_sender
  {U : Type _} (traitsUserSecretInst : traits.UserSecret U) :
  U → wire.core.Envelope → RustM (client.plaintext.Plaintext ×
    schemes.message.MessagePublicKey)

/-- [securedrop_protocol_minimal::client::plaintext::{impl core::fmt::Debug for securedrop_protocol_minimal::client::plaintext::Plaintext}::fmt]:
    Source: 'protocol-minimal/src/client/plaintext.rs', lines 6:9-6:14
    Visibility: public -/
axiom client.plaintext.Plaintext.Insts.CoreFmtDebug.fmt
  :
  client.plaintext.Plaintext → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::schemes::metadata::{securedrop_protocol_minimal::schemes::metadata::MetadataPublicKey}::from_bytes]:
    Source: 'protocol-minimal/src/schemes/metadata.rs', lines 195:4-204:5
    Visibility: public -/
axiom schemes.metadata.MetadataPublicKey.from_bytes
  :
  Slice Std.U8 → RustM (core.result.Result schemes.metadata.MetadataPublicKey
    anyhow.Error)

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::decode]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 91:4-95:5 -/
axiom primitives.provider.ristretto255.decode
  :
  Array Std.U8 32#usize → RustM (core.option.Option
    primitives.provider.ristretto255.Point)

/-- [securedrop_protocol_minimal::primitives::provider::ed25519::sign]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 129:4-131:5 -/
axiom primitives.provider.ed25519.sign
  : Slice Std.U8 → Array Std.U8 32#usize → RustM (Array Std.U8 64#usize)

/-- [securedrop_protocol_minimal::schemes::sign::{impl securedrop_protocol_minimal::schemes::sign::DomainTag for securedrop_protocol_minimal::schemes::sign::JournalistEphemeralKey}::tag]:
    Source: 'protocol-minimal/src/schemes/sign.rs', lines 68:4-70:5
    Visibility: public -/
axiom
  schemes.sign.JournalistEphemeralKey.Insts.Securedrop_protocol_minimalSchemesSignDomainTag.tag
  : RustM (Slice Std.U8)

/-- [securedrop_protocol_minimal::primitives::provider::sha2::sha512]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 244:4-246:5 -/
axiom primitives.provider.sha2.sha512
  : Slice Std.U8 → RustM (Array Std.U8 64#usize)

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::from_uniform_bytes]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 82:4-84:5 -/
axiom primitives.provider.ristretto255.from_uniform_bytes
  : Array Std.U8 64#usize → RustM primitives.provider.ristretto255.Point

/-- [securedrop_protocol_minimal::schemes::sign::{impl securedrop_protocol_minimal::schemes::sign::DomainTag for securedrop_protocol_minimal::schemes::sign::JournalistLongTermKey}::tag]:
    Source: 'protocol-minimal/src/schemes/sign.rs', lines 63:4-65:5
    Visibility: public -/
axiom
  schemes.sign.JournalistLongTermKey.Insts.Securedrop_protocol_minimalSchemesSignDomainTag.tag
  : RustM (Slice Std.U8)

/-- [securedrop_protocol_minimal::journalist::{securedrop_protocol_minimal::journalist::Journalist}::new]:
    Source: 'protocol-minimal/src/journalist.rs', lines 194:4-225:5
    Visibility: public -/
axiom journalist.Journalist.new
  {R : Type _} {Clause1_Clause1_Clause0_Error : Type _} (rand_coreRngCoreInst :
  rand_core.RngCore R) (rand_coreCryptoRngInst : rand_core.CryptoRng R
  Clause1_Clause1_Clause0_Error) :
  R → Std.Usize → RustM (journalist.Journalist × R)

/-- [securedrop_protocol_minimal::journalist::{securedrop_protocol_minimal::journalist::Journalist}::public]:
    Source: 'protocol-minimal/src/journalist.rs', lines 228:4-235:5
    Visibility: public -/
axiom journalist.Journalist.public
  :
  journalist.Journalist → Std.Usize → RustM journalist.JournalistPublicView

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::scalar_encode]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 74:4-76:5 -/
axiom primitives.provider.ristretto255.scalar_encode
  : primitives.provider.ristretto255.Scalar → RustM (Array Std.U8 32#usize)

/-- [securedrop_protocol_minimal::journalist::{securedrop_protocol_minimal::journalist::Journalist}::from_long_term_bytes]:
    Source: 'protocol-minimal/src/journalist.rs', lines 261:4-303:5
    Visibility: public -/
axiom journalist.Journalist.from_long_term_bytes
  :
  journalist.JournalistLongTermBytes → RustM (core.result.Result
    journalist.Journalist anyhow.Error)

/-- [securedrop_protocol_minimal::journalist::{securedrop_protocol_minimal::journalist::Journalist}::generate_ephemeral_bundles]:
    Source: 'protocol-minimal/src/journalist.rs', lines 312:4-316:5
    Visibility: public -/
axiom journalist.Journalist.generate_ephemeral_bundles
  {R : Type _} {Clause1_Clause1_Clause0_Error : Type _} (rand_coreRngCoreInst :
  rand_core.RngCore R) (rand_coreCryptoRngInst : rand_core.CryptoRng R
  Clause1_Clause1_Clause0_Error) :
  journalist.Journalist → R → Std.Usize → RustM (journalist.Journalist ×
    R)

/-- [securedrop_protocol_minimal::journalist::{securedrop_protocol_minimal::journalist::Journalist}::ephemeral_bundle_bytes]:
    Source: 'protocol-minimal/src/journalist.rs', lines 323:4-328:5
    Visibility: public -/
axiom journalist.Journalist.ephemeral_bundle_bytes
  :
  journalist.Journalist → RustM (alloc.vec.Vec
    journalist.EphemeralBundleBytes)

/-- [securedrop_protocol_minimal::journalist::{securedrop_protocol_minimal::journalist::Journalist}::load_ephemeral_bundles]:
    Source: 'protocol-minimal/src/journalist.rs', lines 334:4-339:5
    Visibility: public -/
axiom journalist.Journalist.load_ephemeral_bundles
  :
  journalist.Journalist → alloc.vec.Vec journalist.EphemeralBundleBytes →
    RustM journalist.Journalist

/-- [securedrop_protocol_minimal::journalist::{securedrop_protocol_minimal::journalist::EphemeralBundleBytes}::into_bundle]:
    Source: 'protocol-minimal/src/journalist.rs', lines 431:4-448:5 -/
axiom journalist.EphemeralBundleBytes.into_bundle
  : journalist.EphemeralBundleBytes → RustM keys.bundle.MessageKeyBundle

/-- [securedrop_protocol_minimal::keys::bundle::{impl core::fmt::Debug for securedrop_protocol_minimal::keys::bundle::KeyBundlePublic}::fmt]:
    Source: 'protocol-minimal/src/keys/bundle.rs', lines 10:9-10:14
    Visibility: public -/
axiom keys.bundle.KeyBundlePublic.Insts.CoreFmtDebug.fmt
  :
  keys.bundle.KeyBundlePublic → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::keys::bundle::{impl core::fmt::Debug for securedrop_protocol_minimal::keys::bundle::LongtermKeyBundle}::fmt]:
    Source: 'protocol-minimal/src/keys/bundle.rs', lines 49:9-49:14
    Visibility: public -/
axiom keys.bundle.LongtermKeyBundle.Insts.CoreFmtDebug.fmt
  :
  keys.bundle.LongtermKeyBundle → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::provider::ed25519::keygen]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 121:4-125:5 -/
axiom primitives.provider.ed25519.keygen
  {R : Type _} {Clause0_Clause1_Clause0_Error : Type _} (rand_coreCryptoRngInst
  : rand_core.CryptoRng R Clause0_Clause1_Clause0_Error) :
  R → RustM ((core.result.Result ((Array Std.U8 32#usize) × (Array Std.U8
    32#usize)) anyhow.Error) × R)

/-- [securedrop_protocol_minimal::primitives::provider::ed25519::secret_to_public]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 146:4-148:5 -/
axiom primitives.provider.ed25519.secret_to_public
  :
  Array Std.U8 32#usize → Array Std.U8 32#usize → RustM (Array Std.U8
    32#usize)

/-- [securedrop_protocol_minimal::primitives::dh_akem::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::dh_akem::DhAkemPublicKey}::fmt]:
    Source: 'protocol-minimal/src/primitives/dh_akem.rs', lines 13:9-13:14
    Visibility: public -/
axiom primitives.dh_akem.DhAkemPublicKey.Insts.CoreFmtDebug.fmt
  :
  primitives.dh_akem.DhAkemPublicKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::dh_akem::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::dh_akem::DhAkemPrivateKey}::fmt]:
    Source: 'protocol-minimal/src/primitives/dh_akem.rs', lines 17:9-17:14
    Visibility: public -/
axiom primitives.dh_akem.DhAkemPrivateKey.Insts.CoreFmtDebug.fmt
  :
  primitives.dh_akem.DhAkemPrivateKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::dh_akem::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::dh_akem::DhAkemSecret}::fmt]:
    Source: 'protocol-minimal/src/primitives/dh_akem.rs', lines 21:9-21:14
    Visibility: public -/
axiom primitives.dh_akem.DhAkemSecret.Insts.CoreFmtDebug.fmt
  :
  primitives.dh_akem.DhAkemSecret → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::provider::mlkem::KEY_GENERATION_SEED_SIZE]
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 191:4-191:96 -/
axiom primitives.provider.mlkem.KEY_GENERATION_SEED_SIZE : RustM Std.Usize

/-- [securedrop_protocol_minimal::primitives::mlkem::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::mlkem::MLKEM768PublicKey}::fmt]:
    Source: 'protocol-minimal/src/primitives/mlkem.rs', lines 16:9-16:14
    Visibility: public -/
axiom primitives.mlkem.MLKEM768PublicKey.Insts.CoreFmtDebug.fmt
  :
  primitives.mlkem.MLKEM768PublicKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::mlkem::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::mlkem::MLKEM768PrivateKey}::fmt]:
    Source: 'protocol-minimal/src/primitives/mlkem.rs', lines 20:9-20:14
    Visibility: public -/
axiom primitives.mlkem.MLKEM768PrivateKey.Insts.CoreFmtDebug.fmt
  :
  primitives.mlkem.MLKEM768PrivateKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::provider::ristretto255::Point}::fmt]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 44:26-44:31
    Visibility: public -/
axiom primitives.provider.ristretto255.Point.Insts.CoreFmtDebug.fmt
  :
  primitives.provider.ristretto255.Point → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::provider::ristretto255::Scalar}::fmt]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 49:26-49:31
    Visibility: public -/
axiom primitives.provider.ristretto255.Scalar.Insts.CoreFmtDebug.fmt
  :
  primitives.provider.ristretto255.Scalar → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::provider::ristretto255::scalar_decode]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 67:4-70:5 -/
axiom primitives.provider.ristretto255.scalar_decode
  :
  Array Std.U8 32#usize → RustM (core.option.Option
    primitives.provider.ristretto255.Scalar)

/-- [securedrop_protocol_minimal::primitives::provider::ed25519::verify]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 135:4-142:5 -/
axiom primitives.provider.ed25519.verify
  :
  Slice Std.U8 → Array Std.U8 32#usize → Array Std.U8 64#usize → RustM
    (core.result.Result Unit anyhow.Error)

/-- [securedrop_protocol_minimal::primitives::provider::uuid_parse::from_slice]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 168:4-170:5 -/
axiom primitives.provider.uuid_parse.from_slice
  : Slice Std.U8 → RustM uuid.Uuid

/-- [securedrop_protocol_minimal::primitives::provider::chacha20poly1305::encrypt]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 213:4-221:5
    Visibility: public -/
axiom primitives.provider.chacha20poly1305.encrypt
  :
  Array Std.U8 32#usize → Slice Std.U8 → Slice Std.U8 → Slice Std.U8 →
    Array Std.U8 12#usize → RustM ((core.result.Result Unit
    libcrux_chacha20poly1305.AeadError) × (Slice Std.U8))

/-- [securedrop_protocol_minimal::primitives::provider::chacha20poly1305::decrypt]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 225:4-233:5
    Visibility: public -/
axiom primitives.provider.chacha20poly1305.decrypt
  :
  Array Std.U8 32#usize → Slice Std.U8 → Slice Std.U8 → Slice Std.U8 →
    Array Std.U8 12#usize → RustM ((core.result.Result Unit
    libcrux_chacha20poly1305.AeadError) × (Slice Std.U8))

/-- [securedrop_protocol_minimal::primitives::provider::sha2::SHA512_LEN]
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 240:4-240:69 -/
axiom primitives.provider.sha2.SHA512_LEN : RustM Std.Usize

/-- [securedrop_protocol_minimal::primitives::provider::hkdf::sha256]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 260:4-267:5 -/
axiom primitives.provider.hkdf.sha256
  :
  Slice Std.U8 → Slice Std.U8 → Slice Std.U8 → Slice Std.U8 → RustM
    ((core.result.Result Unit libcrux_hkdf.ExpandError) × (Slice Std.U8))

/-- [securedrop_protocol_minimal::primitives::provider::constants::LEN_MESSAGE_ID]
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 284:4-284:48 -/
axiom primitives.provider.constants.LEN_MESSAGE_ID : RustM Std.Usize

/-- [securedrop_protocol_minimal::primitives::provider::constants::LEN_KMID]
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 287:4-288:80 -/
axiom primitives.provider.constants.LEN_KMID : RustM Std.Usize

/-- [securedrop_protocol_minimal::primitives::provider::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::provider::NoRngError}::fmt]:
    Source: 'protocol-minimal/src/primitives/provider.rs', lines 294:9-294:14
    Visibility: public -/
axiom primitives.provider.NoRngError.Insts.CoreFmtDebug.fmt
  :
  primitives.provider.NoRngError → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::ristretto255::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::ristretto255::DHPublicKey}::fmt]:
    Source: 'protocol-minimal/src/primitives/ristretto255.rs', lines 22:9-22:14
    Visibility: public -/
axiom primitives.ristretto255.DHPublicKey.Insts.CoreFmtDebug.fmt
  :
  primitives.ristretto255.DHPublicKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::ristretto255::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::ristretto255::DHPrivateKey}::fmt]:
    Source: 'protocol-minimal/src/primitives/ristretto255.rs', lines 29:9-29:14
    Visibility: public -/
axiom primitives.ristretto255.DHPrivateKey.Insts.CoreFmtDebug.fmt
  :
  primitives.ristretto255.DHPrivateKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::xwing::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::xwing::XWingPublicKey}::fmt]:
    Source: 'protocol-minimal/src/primitives/xwing.rs', lines 12:9-12:14
    Visibility: public -/
axiom primitives.xwing.XWingPublicKey.Insts.CoreFmtDebug.fmt
  :
  primitives.xwing.XWingPublicKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::primitives::xwing::{impl core::fmt::Debug for securedrop_protocol_minimal::primitives::xwing::XWingPrivateKey}::fmt]:
    Source: 'protocol-minimal/src/primitives/xwing.rs', lines 16:9-16:14
    Visibility: public -/
axiom primitives.xwing.XWingPrivateKey.Insts.CoreFmtDebug.fmt
  :
  primitives.xwing.XWingPrivateKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::schemes::message::{impl core::fmt::Debug for securedrop_protocol_minimal::schemes::message::MessagePublicKey}::fmt]:
    Source: 'protocol-minimal/src/schemes/message.rs', lines 60:9-60:14
    Visibility: public -/
axiom schemes.message.MessagePublicKey.Insts.CoreFmtDebug.fmt
  :
  schemes.message.MessagePublicKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::schemes::message::{impl core::fmt::Debug for securedrop_protocol_minimal::schemes::message::MessageCiphertext}::fmt]:
    Source: 'protocol-minimal/src/schemes/message.rs', lines 153:9-153:14
    Visibility: public -/
axiom schemes.message.MessageCiphertext.Insts.CoreFmtDebug.fmt
  :
  schemes.message.MessageCiphertext → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::schemes::message::auth_dec]:
    Source: 'protocol-minimal/src/schemes/message.rs', lines 339:0-379:1
    Visibility: public -/
axiom schemes.message.auth_dec
  :
  schemes.message.MessagePrivateKey → schemes.message.MessagePublicKey →
    schemes.message.MessageCiphertext → Slice Std.U8 →
    primitives.ristretto255.DHPublicKey → RustM (core.result.Result
    (alloc.vec.Vec Std.U8) anyhow.Error)

/-- [securedrop_protocol_minimal::schemes::metadata::{impl core::fmt::Debug for securedrop_protocol_minimal::schemes::metadata::MetadataPublicKey}::fmt]:
    Source: 'protocol-minimal/src/schemes/metadata.rs', lines 40:9-40:14
    Visibility: public -/
axiom schemes.metadata.MetadataPublicKey.Insts.CoreFmtDebug.fmt
  :
  schemes.metadata.MetadataPublicKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::schemes::metadata::{impl core::fmt::Debug for securedrop_protocol_minimal::schemes::metadata::MetadataCiphertext}::fmt]:
    Source: 'protocol-minimal/src/schemes/metadata.rs', lines 87:9-87:14
    Visibility: public -/
axiom schemes.metadata.MetadataCiphertext.Insts.CoreFmtDebug.fmt
  :
  schemes.metadata.MetadataCiphertext → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::schemes::metadata::{securedrop_protocol_minimal::schemes::metadata::MetadataCiphertext}::from_bytes]:
    Source: 'protocol-minimal/src/schemes/metadata.rs', lines 114:4-131:5
    Visibility: public -/
axiom schemes.metadata.MetadataCiphertext.from_bytes
  :
  Slice Std.U8 → RustM (core.result.Result
    schemes.metadata.MetadataCiphertext anyhow.Error)

/-- [securedrop_protocol_minimal::schemes::metadata::decrypt]:
    Source: 'protocol-minimal/src/schemes/metadata.rs', lines 280:0-296:1
    Visibility: public -/
axiom schemes.metadata.decrypt
  :
  schemes.metadata.MetadataPrivateKey → schemes.metadata.MetadataCiphertext
    → RustM (core.result.Result (alloc.vec.Vec Std.U8) anyhow.Error)

/-- [securedrop_protocol_minimal::schemes::sign::{impl core::fmt::Debug for securedrop_protocol_minimal::schemes::sign::JournalistLongTermKey}::fmt]:
    Source: 'protocol-minimal/src/schemes/sign.rs', lines 37:9-37:14
    Visibility: public -/
axiom schemes.sign.JournalistLongTermKey.Insts.CoreFmtDebug.fmt
  :
  schemes.sign.JournalistLongTermKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::schemes::sign::{impl core::fmt::Debug for securedrop_protocol_minimal::schemes::sign::JournalistEphemeralKey}::fmt]:
    Source: 'protocol-minimal/src/schemes/sign.rs', lines 41:9-41:14
    Visibility: public -/
axiom schemes.sign.JournalistEphemeralKey.Insts.CoreFmtDebug.fmt
  :
  schemes.sign.JournalistEphemeralKey → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::schemes::sign::{impl core::fmt::Debug for securedrop_protocol_minimal::schemes::sign::NewsroomOnJournalist}::fmt]:
    Source: 'protocol-minimal/src/schemes/sign.rs', lines 45:9-45:14
    Visibility: public -/
axiom schemes.sign.NewsroomOnJournalist.Insts.CoreFmtDebug.fmt
  :
  schemes.sign.NewsroomOnJournalist → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::schemes::sign::{impl core::fmt::Debug for securedrop_protocol_minimal::schemes::sign::FpfOnNewsroom}::fmt]:
    Source: 'protocol-minimal/src/schemes/sign.rs', lines 49:9-49:14
    Visibility: public -/
axiom schemes.sign.FpfOnNewsroom.Insts.CoreFmtDebug.fmt
  :
  schemes.sign.FpfOnNewsroom → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::schemes::sign::{impl securedrop_protocol_minimal::schemes::sign::DomainTag for securedrop_protocol_minimal::schemes::sign::NewsroomOnJournalist}::tag]:
    Source: 'protocol-minimal/src/schemes/sign.rs', lines 73:4-75:5
    Visibility: public -/
axiom
  schemes.sign.NewsroomOnJournalist.Insts.Securedrop_protocol_minimalSchemesSignDomainTag.tag
  : RustM (Slice Std.U8)

/-- [securedrop_protocol_minimal::schemes::sign::{impl securedrop_protocol_minimal::schemes::sign::DomainTag for securedrop_protocol_minimal::schemes::sign::FpfOnNewsroom}::tag]:
    Source: 'protocol-minimal/src/schemes/sign.rs', lines 78:4-80:5
    Visibility: public -/
axiom
  schemes.sign.FpfOnNewsroom.Insts.Securedrop_protocol_minimalSchemesSignDomainTag.tag
  : RustM (Slice Std.U8)

/-- [securedrop_protocol_minimal::server::challenge::sort_by_id]:
    Source: 'protocol-minimal/src/server/challenge.rs', lines 14:0-16:1 -/
axiom server.challenge.sort_by_id
  : Slice wire.core.FetchResponse → RustM (Slice wire.core.FetchResponse)

/-- [securedrop_protocol_minimal::server::challenge::compute_fetch_challenges]:
    Source: 'protocol-minimal/src/server/challenge.rs', lines 26:0-64:1
    Visibility: public -/
axiom server.challenge.compute_fetch_challenges
  {R : Type _} {Clause1_Clause1_Clause0_Error : Type _} (rand_coreRngCoreInst :
  rand_core.RngCore R) (rand_coreCryptoRngInst : rand_core.CryptoRng R
  Clause1_Clause1_Clause0_Error) :
  R → Slice ((Array Std.U8 16#usize) × wire.core.Envelope) → Std.Usize →
    RustM ((alloc.vec.Vec wire.core.FetchResponse) × R)

/-- [securedrop_protocol_minimal::source::{impl core::fmt::Debug for securedrop_protocol_minimal::source::SourcePublicView}::fmt]:
    Source: 'protocol-minimal/src/source.rs', lines 54:9-54:14
    Visibility: public -/
axiom source.SourcePublicView.Insts.CoreFmtDebug.fmt
  :
  source.SourcePublicView → core.fmt.Formatter → RustM ((core.result.Result
    Unit core.fmt.Error) × core.fmt.Formatter × (core.fmt.Formatter →
    core.fmt.Formatter))

/-- [securedrop_protocol_minimal::source::{impl securedrop_protocol_minimal::traits::UserSecret for securedrop_protocol_minimal::source::Source}::keybundles]:
    Source: 'protocol-minimal/src/source.rs', lines 110:4-112:5
    Visibility: public -/
axiom
  source.Source.Insts.Securedrop_protocol_minimalTraitsUserSecret.keybundles
  : source.Source → RustM (alloc.vec.Vec keys.bundle.MessageKeyBundle)

/-- [securedrop_protocol_minimal::source::{securedrop_protocol_minimal::source::Source}::new]:
    Source: 'protocol-minimal/src/source.rs', lines 118:4-123:5
    Visibility: public -/
axiom source.Source.new
  {R : Type _} {Clause1_Clause1_Clause0_Error : Type _} (rand_coreRngCoreInst :
  rand_core.RngCore R) (rand_coreCryptoRngInst : rand_core.CryptoRng R
  Clause1_Clause1_Clause0_Error) :
  R → RustM source.Source

/-- [securedrop_protocol_minimal::source::{securedrop_protocol_minimal::source::Source}::passphrase]:
    Source: 'protocol-minimal/src/source.rs', lines 132:4-134:5
    Visibility: public -/
axiom source.Source.impl.passphrase : source.Source → RustM Str

/-- [securedrop_protocol_minimal::source::{securedrop_protocol_minimal::source::Source}::from_passphrase]:
    Source: 'protocol-minimal/src/source.rs', lines 144:4-158:5
    Visibility: public -/
axiom source.Source.from_passphrase
  : Str → RustM (core.result.Result source.Source anyhow.Error)

/-- [securedrop_protocol_minimal::source::{securedrop_protocol_minimal::source::Source}::from_master_key]:
    Source: 'protocol-minimal/src/source.rs', lines 166:4-210:5 -/
axiom source.Source.from_master_key
  : Array Std.U8 16#usize → alloc.string.String → RustM source.Source

/-- [securedrop_protocol_minimal::wire::bundle::{impl core::fmt::Debug for securedrop_protocol_minimal::wire::bundle::SignedLongtermKeyBundle}::fmt]:
    Source: 'protocol-minimal/src/wire/bundle.rs', lines 15:9-15:14
    Visibility: public -/
axiom wire.bundle.SignedLongtermKeyBundle.Insts.CoreFmtDebug.fmt
  :
  wire.bundle.SignedLongtermKeyBundle → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::wire::core::{impl core::fmt::Debug for securedrop_protocol_minimal::wire::core::FetchResponse}::fmt]:
    Source: 'protocol-minimal/src/wire/core.rs', lines 94:16-94:21
    Visibility: public -/
axiom wire.core.FetchResponse.Insts.CoreFmtDebug.fmt
  :
  wire.core.FetchResponse → core.fmt.Formatter → RustM ((core.result.Result
    Unit core.fmt.Error) × core.fmt.Formatter × (core.fmt.Formatter →
    core.fmt.Formatter))

/-- [securedrop_protocol_minimal::wire::core::{impl core::fmt::Debug for securedrop_protocol_minimal::wire::core::Envelope}::fmt]:
    Source: 'protocol-minimal/src/wire/core.rs', lines 116:9-116:14
    Visibility: public -/
axiom wire.core.Envelope.Insts.CoreFmtDebug.fmt
  :
  wire.core.Envelope → core.fmt.Formatter → RustM ((core.result.Result Unit
    core.fmt.Error) × core.fmt.Formatter × (core.fmt.Formatter →
    core.fmt.Formatter))

/-- [securedrop_protocol_minimal::wire::enrollment::{impl core::fmt::Debug for securedrop_protocol_minimal::wire::enrollment::Enrollment}::fmt]:
    Source: 'protocol-minimal/src/wire/enrollment.rs', lines 6:16-6:21
    Visibility: public -/
axiom wire.enrollment.Enrollment.Insts.CoreFmtDebug.fmt
  :
  wire.enrollment.Enrollment → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::wire::setup::{impl core::fmt::Debug for securedrop_protocol_minimal::wire::setup::NewsroomSetupRequest}::fmt]:
    Source: 'protocol-minimal/src/wire/setup.rs', lines 19:9-19:14
    Visibility: public -/
axiom wire.setup.NewsroomSetupRequest.Insts.CoreFmtDebug.fmt
  :
  wire.setup.NewsroomSetupRequest → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::wire::setup::{impl core::fmt::Debug for securedrop_protocol_minimal::wire::setup::NewsroomSetupResponse}::fmt]:
    Source: 'protocol-minimal/src/wire/setup.rs', lines 27:9-27:14
    Visibility: public -/
axiom wire.setup.NewsroomSetupResponse.Insts.CoreFmtDebug.fmt
  :
  wire.setup.NewsroomSetupResponse → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::wire::setup::{impl core::fmt::Debug for securedrop_protocol_minimal::wire::setup::JournalistSetupRequest}::fmt]:
    Source: 'protocol-minimal/src/wire/setup.rs', lines 36:9-36:14
    Visibility: public -/
axiom wire.setup.JournalistSetupRequest.Insts.CoreFmtDebug.fmt
  :
  wire.setup.JournalistSetupRequest → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::wire::setup::{impl core::fmt::Debug for securedrop_protocol_minimal::wire::setup::JournalistSetupResponse}::fmt]:
    Source: 'protocol-minimal/src/wire/setup.rs', lines 45:9-45:14
    Visibility: public -/
axiom wire.setup.JournalistSetupResponse.Insts.CoreFmtDebug.fmt
  :
  wire.setup.JournalistSetupResponse → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::wire::setup::{impl core::fmt::Debug for securedrop_protocol_minimal::wire::setup::JournalistEphemeralKeyRequest}::fmt]:
    Source: 'protocol-minimal/src/wire/setup.rs', lines 55:9-55:14
    Visibility: public -/
axiom wire.setup.JournalistEphemeralKeyRequest.Insts.CoreFmtDebug.fmt
  :
  wire.setup.JournalistEphemeralKeyRequest → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

/-- [securedrop_protocol_minimal::wire::setup::{impl core::fmt::Debug for securedrop_protocol_minimal::wire::setup::JournalistEphemeralKeyResponse}::fmt]:
    Source: 'protocol-minimal/src/wire/setup.rs', lines 68:9-68:14
    Visibility: public -/
axiom wire.setup.JournalistEphemeralKeyResponse.Insts.CoreFmtDebug.fmt
  :
  wire.setup.JournalistEphemeralKeyResponse → core.fmt.Formatter → RustM
    ((core.result.Result Unit core.fmt.Error) × core.fmt.Formatter ×
    (core.fmt.Formatter → core.fmt.Formatter))

