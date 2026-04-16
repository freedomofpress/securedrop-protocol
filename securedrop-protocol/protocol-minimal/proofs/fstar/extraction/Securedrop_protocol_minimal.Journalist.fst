module Securedrop_protocol_minimal.Journalist
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_JournalistPublicView = {
  f_vk:Securedrop_protocol_minimal.Sign.t_VerifyingKey;
  f_fetch_pk:Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey;
  f_reply_apke_pk:Securedrop_protocol_minimal.Message.t_MessagePublicKey;
  f_signed_longterm_key_bytes:Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes;
  f_selfsig:Securedrop_protocol_minimal.Sign.t_Signature
  Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey;
  f_kb:(Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
    Securedrop_protocol_minimal.Sign.t_Signature
    Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey)
}

let impl_JournalistPublicView__new
      (vk: Securedrop_protocol_minimal.Sign.t_VerifyingKey)
      (fetch: Securedrop_protocol_minimal.Primitives.X25519.t_DHPublicKey)
      (reply_apke: Securedrop_protocol_minimal.Message.t_MessagePublicKey)
      (selfsig:
          Securedrop_protocol_minimal.Sign.t_Signature
          Securedrop_protocol_minimal.Sign.t_JournalistLongTermKey)
      (signed_longterm_key_bytes: Securedrop_protocol_minimal.Keys.t_SignedLongtermPubKeyBytes)
      (kb:
          (Securedrop_protocol_minimal.Keys.t_KeyBundlePublic &
            Securedrop_protocol_minimal.Sign.t_Signature
            Securedrop_protocol_minimal.Sign.t_JournalistEphemeralKey))
    : t_JournalistPublicView =
  {
    f_vk = vk;
    f_fetch_pk = fetch;
    f_reply_apke_pk = reply_apke;
    f_selfsig = selfsig;
    f_signed_longterm_key_bytes = signed_longterm_key_bytes;
    f_kb = kb
  }
  <:
  t_JournalistPublicView
