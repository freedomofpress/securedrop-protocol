module Securedrop_protocol
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

let _ =
  (* This module has implicit dependencies, here we make them explicit. *)
  (* The implicit dependencies arise from typeclasses instances. *)
  let open Getrandom.Error in
  let open Js_sys in
  let open Rand_chacha.Chacha in
  let open Rand_core in
  let open Securedrop_protocol.Bench.Encrypt_decrypt in
  let open Wasm_bindgen.Convert.Traits in
  let open Wasm_bindgen.Describe in
  ()

let rng_from_seed (seed32: t_Array u8 (mk_usize 32)) : Rand_chacha.Chacha.t_ChaCha20Rng =
  Rand_core.f_from_seed #Rand_chacha.Chacha.t_ChaCha20Rng #FStar.Tactics.Typeclasses.solve seed32

type t_WSource = { f_inner:Securedrop_protocol.Bench.Encrypt_decrypt.t_Source }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_2': Wasm_bindgen.__rt.Marker.t_SupportsConstructor t_WSource

unfold
let impl_2 = impl_2'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_3': Wasm_bindgen.__rt.Marker.t_SupportsInstanceProperty t_WSource

unfold
let impl_3 = impl_3'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_4': Wasm_bindgen.__rt.Marker.t_SupportsStaticProperty t_WSource

unfold
let impl_4 = impl_4'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_5': Wasm_bindgen.Describe.t_WasmDescribe t_WSource

unfold
let impl_5 = impl_5'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_6': Wasm_bindgen.Convert.Traits.t_IntoWasmAbi t_WSource

unfold
let impl_6 = impl_6'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_7': Wasm_bindgen.Convert.Traits.t_FromWasmAbi t_WSource

unfold
let impl_7 = impl_7'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_8': Core_models.Convert.t_From Wasm_bindgen.t_JsValue t_WSource

unfold
let impl_8 = impl_8'

assume
val f_from__impl_8__e_ee_wbg_wsource_new': u32 -> u32

unfold
let f_from__impl_8__e_ee_wbg_wsource_new = f_from__impl_8__e_ee_wbg_wsource_new'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_9': Wasm_bindgen.Convert.Traits.t_RefFromWasmAbi t_WSource

unfold
let impl_9 = impl_9'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_10': Wasm_bindgen.Convert.Traits.t_RefMutFromWasmAbi t_WSource

unfold
let impl_10 = impl_10'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_11': Wasm_bindgen.Convert.Traits.t_LongRefFromWasmAbi t_WSource

unfold
let impl_11 = impl_11'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_12': Wasm_bindgen.Convert.Traits.t_OptionIntoWasmAbi t_WSource

unfold
let impl_12 = impl_12'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_13': Wasm_bindgen.Convert.Traits.t_OptionFromWasmAbi t_WSource

unfold
let impl_13 = impl_13'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_14': Wasm_bindgen.Convert.Traits.t_TryFromJsValue t_WSource

unfold
let impl_14 = impl_14'

assume
val f_try_from_js_value_ref__impl_14__e_ee_wbg_wsource_unwrap': u32 -> u32

unfold
let f_try_from_js_value_ref__impl_14__e_ee_wbg_wsource_unwrap =
  f_try_from_js_value_ref__impl_14__e_ee_wbg_wsource_unwrap'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_15': Wasm_bindgen.Describe.t_WasmDescribeVector t_WSource

unfold
let impl_15 = impl_15'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_16': Wasm_bindgen.Convert.Traits.t_VectorIntoWasmAbi t_WSource

unfold
let impl_16 = impl_16'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_17': Wasm_bindgen.Convert.Traits.t_VectorFromWasmAbi t_WSource

unfold
let impl_17 = impl_17'

/// Construct a Source (actor setup randomness is outside timed paths).
let impl_WSource__new (_: Prims.unit) : t_WSource =
  let seed:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let
  (tmp0: t_Array u8 (mk_usize 32)),
  (out: Core_models.Result.t_Result Prims.unit Getrandom.Error.t_Error) =
    Getrandom.fill seed
  in
  let seed:t_Array u8 (mk_usize 32) = tmp0 in
  let _:Prims.unit =
    Core_models.Result.impl__expect #Prims.unit #Getrandom.Error.t_Error out "getrandom failed"
  in
  let rng:Rand_chacha.Chacha.t_ChaCha20Rng = rng_from_seed seed in
  let
  (tmp0: Rand_chacha.Chacha.t_ChaCha20Rng),
  (out: Securedrop_protocol.Bench.Encrypt_decrypt.t_Source) =
    Securedrop_protocol.Bench.Encrypt_decrypt.impl_Source__new #Rand_chacha.Chacha.t_ChaCha20Rng rng
  in
  let rng:Rand_chacha.Chacha.t_ChaCha20Rng = tmp0 in
  { f_inner = out } <: t_WSource

assume
val impl_WSource__new__e_': Prims.unit

unfold
let impl_WSource__new__e_ = impl_WSource__new__e_'

/// Construct a Source (actor setup randomness is outside timed paths).
assume
val impl_WSource__new__e___e_ee_wasm_bindgen_generated_WSource_new': Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_WSource__new__e___e_ee_wasm_bindgen_generated_WSource_new =
  impl_WSource__new__e___e_ee_wasm_bindgen_generated_WSource_new'

assume
val impl_WSource__new__e___e_ee_wasm_bindgen_generated_WSource_new__e_': Prims.unit

unfold
let impl_WSource__new__e___e_ee_wasm_bindgen_generated_WSource_new__e_ =
  impl_WSource__new__e___e_ee_wasm_bindgen_generated_WSource_new__e_'

type t_WJournalist = { f_inner:Securedrop_protocol.Bench.Encrypt_decrypt.t_Journalist }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_19': Wasm_bindgen.__rt.Marker.t_SupportsConstructor t_WJournalist

unfold
let impl_19 = impl_19'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_20': Wasm_bindgen.__rt.Marker.t_SupportsInstanceProperty t_WJournalist

unfold
let impl_20 = impl_20'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_21': Wasm_bindgen.__rt.Marker.t_SupportsStaticProperty t_WJournalist

unfold
let impl_21 = impl_21'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_22': Wasm_bindgen.Describe.t_WasmDescribe t_WJournalist

unfold
let impl_22 = impl_22'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_23': Wasm_bindgen.Convert.Traits.t_IntoWasmAbi t_WJournalist

unfold
let impl_23 = impl_23'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_24': Wasm_bindgen.Convert.Traits.t_FromWasmAbi t_WJournalist

unfold
let impl_24 = impl_24'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_25': Core_models.Convert.t_From Wasm_bindgen.t_JsValue t_WJournalist

unfold
let impl_25 = impl_25'

assume
val f_from__impl_25__e_ee_wbg_wjournalist_new': u32 -> u32

unfold
let f_from__impl_25__e_ee_wbg_wjournalist_new = f_from__impl_25__e_ee_wbg_wjournalist_new'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_26': Wasm_bindgen.Convert.Traits.t_RefFromWasmAbi t_WJournalist

unfold
let impl_26 = impl_26'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_27': Wasm_bindgen.Convert.Traits.t_RefMutFromWasmAbi t_WJournalist

unfold
let impl_27 = impl_27'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_28': Wasm_bindgen.Convert.Traits.t_LongRefFromWasmAbi t_WJournalist

unfold
let impl_28 = impl_28'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_29': Wasm_bindgen.Convert.Traits.t_OptionIntoWasmAbi t_WJournalist

unfold
let impl_29 = impl_29'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_30': Wasm_bindgen.Convert.Traits.t_OptionFromWasmAbi t_WJournalist

unfold
let impl_30 = impl_30'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_31': Wasm_bindgen.Convert.Traits.t_TryFromJsValue t_WJournalist

unfold
let impl_31 = impl_31'

assume
val f_try_from_js_value_ref__impl_31__e_ee_wbg_wjournalist_unwrap': u32 -> u32

unfold
let f_try_from_js_value_ref__impl_31__e_ee_wbg_wjournalist_unwrap =
  f_try_from_js_value_ref__impl_31__e_ee_wbg_wjournalist_unwrap'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_32': Wasm_bindgen.Describe.t_WasmDescribeVector t_WJournalist

unfold
let impl_32 = impl_32'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_33': Wasm_bindgen.Convert.Traits.t_VectorIntoWasmAbi t_WJournalist

unfold
let impl_33 = impl_33'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_34': Wasm_bindgen.Convert.Traits.t_VectorFromWasmAbi t_WJournalist

unfold
let impl_34 = impl_34'

/// Construct a Journalist with `num_keybundles` short-lived bundles.
let impl_WJournalist__new (num_keybundles: usize) : t_WJournalist =
  let seed:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let
  (tmp0: t_Array u8 (mk_usize 32)),
  (out: Core_models.Result.t_Result Prims.unit Getrandom.Error.t_Error) =
    Getrandom.fill seed
  in
  let seed:t_Array u8 (mk_usize 32) = tmp0 in
  let _:Prims.unit =
    Core_models.Result.impl__expect #Prims.unit #Getrandom.Error.t_Error out "getrandom failed"
  in
  let rng:Rand_chacha.Chacha.t_ChaCha20Rng = rng_from_seed seed in
  let
  (tmp0: Rand_chacha.Chacha.t_ChaCha20Rng),
  (out: Securedrop_protocol.Bench.Encrypt_decrypt.t_Journalist) =
    Securedrop_protocol.Bench.Encrypt_decrypt.impl_Journalist__new #Rand_chacha.Chacha.t_ChaCha20Rng
      rng
      num_keybundles
  in
  let rng:Rand_chacha.Chacha.t_ChaCha20Rng = tmp0 in
  { f_inner = out } <: t_WJournalist

let impl_WJournalist__keybundles (self: t_WJournalist) : usize =
  Core_models.Slice.impl__len #Securedrop_protocol.Bench.Encrypt_decrypt.t_KeyBundle
    (Securedrop_protocol.Bench.Encrypt_decrypt.f_get_all_keys #Securedrop_protocol.Bench.Encrypt_decrypt.t_Journalist
        #FStar.Tactics.Typeclasses.solve
        self.f_inner
      <:
      t_Slice Securedrop_protocol.Bench.Encrypt_decrypt.t_KeyBundle)

assume
val impl_WJournalist__new__e_': Prims.unit

unfold
let impl_WJournalist__new__e_ = impl_WJournalist__new__e_'

/// Construct a Journalist with `num_keybundles` short-lived bundles.
assume
val impl_WJournalist__new__e___e_ee_wasm_bindgen_generated_WJournalist_new':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_WJournalist__new__e___e_ee_wasm_bindgen_generated_WJournalist_new =
  impl_WJournalist__new__e___e_ee_wasm_bindgen_generated_WJournalist_new'

assume
val impl_WJournalist__new__e___e_ee_wasm_bindgen_generated_WJournalist_new__e_': Prims.unit

unfold
let impl_WJournalist__new__e___e_ee_wasm_bindgen_generated_WJournalist_new__e_ =
  impl_WJournalist__new__e___e_ee_wasm_bindgen_generated_WJournalist_new__e_'

assume
val impl_WJournalist__keybundles__e_': Prims.unit

unfold
let impl_WJournalist__keybundles__e_ = impl_WJournalist__keybundles__e_'

assume
val impl_WJournalist__keybundles__e___e_ee_wasm_bindgen_generated_WJournalist_keybundles': me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_WJournalist__keybundles__e___e_ee_wasm_bindgen_generated_WJournalist_keybundles =
  impl_WJournalist__keybundles__e___e_ee_wasm_bindgen_generated_WJournalist_keybundles'

assume
val impl_WJournalist__keybundles__e___e_ee_wasm_bindgen_generated_WJournalist_keybundles__e_': Prims.unit

unfold
let impl_WJournalist__keybundles__e___e_ee_wasm_bindgen_generated_WJournalist_keybundles__e_ =
  impl_WJournalist__keybundles__e___e_ee_wasm_bindgen_generated_WJournalist_keybundles__e_'

type t_WEnvelope = { f_inner:Securedrop_protocol.Bench.Encrypt_decrypt.t_Envelope }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_36': Wasm_bindgen.__rt.Marker.t_SupportsConstructor t_WEnvelope

unfold
let impl_36 = impl_36'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_37': Wasm_bindgen.__rt.Marker.t_SupportsInstanceProperty t_WEnvelope

unfold
let impl_37 = impl_37'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_38': Wasm_bindgen.__rt.Marker.t_SupportsStaticProperty t_WEnvelope

unfold
let impl_38 = impl_38'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_39': Wasm_bindgen.Describe.t_WasmDescribe t_WEnvelope

unfold
let impl_39 = impl_39'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_40': Wasm_bindgen.Convert.Traits.t_IntoWasmAbi t_WEnvelope

unfold
let impl_40 = impl_40'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_41': Wasm_bindgen.Convert.Traits.t_FromWasmAbi t_WEnvelope

unfold
let impl_41 = impl_41'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_42': Core_models.Convert.t_From Wasm_bindgen.t_JsValue t_WEnvelope

unfold
let impl_42 = impl_42'

assume
val f_from__impl_42__e_ee_wbg_wenvelope_new': u32 -> u32

unfold
let f_from__impl_42__e_ee_wbg_wenvelope_new = f_from__impl_42__e_ee_wbg_wenvelope_new'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_43': Wasm_bindgen.Convert.Traits.t_RefFromWasmAbi t_WEnvelope

unfold
let impl_43 = impl_43'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_44': Wasm_bindgen.Convert.Traits.t_RefMutFromWasmAbi t_WEnvelope

unfold
let impl_44 = impl_44'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_45': Wasm_bindgen.Convert.Traits.t_LongRefFromWasmAbi t_WEnvelope

unfold
let impl_45 = impl_45'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_46': Wasm_bindgen.Convert.Traits.t_OptionIntoWasmAbi t_WEnvelope

unfold
let impl_46 = impl_46'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_47': Wasm_bindgen.Convert.Traits.t_OptionFromWasmAbi t_WEnvelope

unfold
let impl_47 = impl_47'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_48': Wasm_bindgen.Convert.Traits.t_TryFromJsValue t_WEnvelope

unfold
let impl_48 = impl_48'

assume
val f_try_from_js_value_ref__impl_48__e_ee_wbg_wenvelope_unwrap': u32 -> u32

unfold
let f_try_from_js_value_ref__impl_48__e_ee_wbg_wenvelope_unwrap =
  f_try_from_js_value_ref__impl_48__e_ee_wbg_wenvelope_unwrap'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_49': Wasm_bindgen.Describe.t_WasmDescribeVector t_WEnvelope

unfold
let impl_49 = impl_49'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_50': Wasm_bindgen.Convert.Traits.t_VectorIntoWasmAbi t_WEnvelope

unfold
let impl_50 = impl_50'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_51': Wasm_bindgen.Convert.Traits.t_VectorFromWasmAbi t_WEnvelope

unfold
let impl_51 = impl_51'

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl: Core_models.Convert.t_From t_WEnvelope
  Securedrop_protocol.Bench.Encrypt_decrypt.t_Envelope =
  {
    f_from_pre = (fun (inner: Securedrop_protocol.Bench.Encrypt_decrypt.t_Envelope) -> true);
    f_from_post
    =
    (fun (inner: Securedrop_protocol.Bench.Encrypt_decrypt.t_Envelope) (out: t_WEnvelope) -> true);
    f_from
    =
    fun (inner: Securedrop_protocol.Bench.Encrypt_decrypt.t_Envelope) ->
      { f_inner = inner } <: t_WEnvelope
  }

/// Size hint to mirror the Rust bench’s “sink” usage.
let impl_WEnvelope__size_hint (self: t_WEnvelope) : usize =
  (Securedrop_protocol.Bench.Encrypt_decrypt.impl_Envelope__cmessage_len self.f_inner <: usize) +!
  (Securedrop_protocol.Bench.Encrypt_decrypt.impl_Envelope__cmetadata_len self.f_inner <: usize)

assume
val impl_WEnvelope__size_hint__e_': Prims.unit

unfold
let impl_WEnvelope__size_hint__e_ = impl_WEnvelope__size_hint__e_'

/// Size hint to mirror the Rust bench’s “sink” usage.
assume
val impl_WEnvelope__size_hint__e___e_ee_wasm_bindgen_generated_WEnvelope_size_hint': me: u32
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_WEnvelope__size_hint__e___e_ee_wasm_bindgen_generated_WEnvelope_size_hint =
  impl_WEnvelope__size_hint__e___e_ee_wasm_bindgen_generated_WEnvelope_size_hint'

assume
val impl_WEnvelope__size_hint__e___e_ee_wasm_bindgen_generated_WEnvelope_size_hint__e_': Prims.unit

unfold
let impl_WEnvelope__size_hint__e___e_ee_wasm_bindgen_generated_WEnvelope_size_hint__e_ =
  impl_WEnvelope__size_hint__e___e_ee_wasm_bindgen_generated_WEnvelope_size_hint__e_'

type t_WFetchResponse = { f_inner:Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_53': Wasm_bindgen.__rt.Marker.t_SupportsConstructor t_WFetchResponse

unfold
let impl_53 = impl_53'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_54': Wasm_bindgen.__rt.Marker.t_SupportsInstanceProperty t_WFetchResponse

unfold
let impl_54 = impl_54'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_55': Wasm_bindgen.__rt.Marker.t_SupportsStaticProperty t_WFetchResponse

unfold
let impl_55 = impl_55'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_56': Wasm_bindgen.Describe.t_WasmDescribe t_WFetchResponse

unfold
let impl_56 = impl_56'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_57': Wasm_bindgen.Convert.Traits.t_IntoWasmAbi t_WFetchResponse

unfold
let impl_57 = impl_57'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_58': Wasm_bindgen.Convert.Traits.t_FromWasmAbi t_WFetchResponse

unfold
let impl_58 = impl_58'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_59': Core_models.Convert.t_From Wasm_bindgen.t_JsValue t_WFetchResponse

unfold
let impl_59 = impl_59'

assume
val f_from__impl_59__e_ee_wbg_wfetchresponse_new': u32 -> u32

unfold
let f_from__impl_59__e_ee_wbg_wfetchresponse_new = f_from__impl_59__e_ee_wbg_wfetchresponse_new'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_60': Wasm_bindgen.Convert.Traits.t_RefFromWasmAbi t_WFetchResponse

unfold
let impl_60 = impl_60'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_61': Wasm_bindgen.Convert.Traits.t_RefMutFromWasmAbi t_WFetchResponse

unfold
let impl_61 = impl_61'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_62': Wasm_bindgen.Convert.Traits.t_LongRefFromWasmAbi t_WFetchResponse

unfold
let impl_62 = impl_62'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_63': Wasm_bindgen.Convert.Traits.t_OptionIntoWasmAbi t_WFetchResponse

unfold
let impl_63 = impl_63'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_64': Wasm_bindgen.Convert.Traits.t_OptionFromWasmAbi t_WFetchResponse

unfold
let impl_64 = impl_64'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_65': Wasm_bindgen.Convert.Traits.t_TryFromJsValue t_WFetchResponse

unfold
let impl_65 = impl_65'

assume
val f_try_from_js_value_ref__impl_65__e_ee_wbg_wfetchresponse_unwrap': u32 -> u32

unfold
let f_try_from_js_value_ref__impl_65__e_ee_wbg_wfetchresponse_unwrap =
  f_try_from_js_value_ref__impl_65__e_ee_wbg_wfetchresponse_unwrap'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_66': Wasm_bindgen.Describe.t_WasmDescribeVector t_WFetchResponse

unfold
let impl_66 = impl_66'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_67': Wasm_bindgen.Convert.Traits.t_VectorIntoWasmAbi t_WFetchResponse

unfold
let impl_67 = impl_67'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_68': Wasm_bindgen.Convert.Traits.t_VectorFromWasmAbi t_WFetchResponse

unfold
let impl_68 = impl_68'

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl_1: Core_models.Convert.t_From t_WFetchResponse
  Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse =
  {
    f_from_pre = (fun (inner: Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse) -> true);
    f_from_post
    =
    (fun
        (inner: Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse)
        (out: t_WFetchResponse)
        ->
        true);
    f_from
    =
    fun (inner: Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse) ->
      { f_inner = inner } <: t_WFetchResponse
  }

type t_WStoreEntry = { f_inner:Securedrop_protocol.Bench.Encrypt_decrypt.t_ServerMessageStore }

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_69': Wasm_bindgen.__rt.Marker.t_SupportsConstructor t_WStoreEntry

unfold
let impl_69 = impl_69'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_70': Wasm_bindgen.__rt.Marker.t_SupportsInstanceProperty t_WStoreEntry

unfold
let impl_70 = impl_70'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_71': Wasm_bindgen.__rt.Marker.t_SupportsStaticProperty t_WStoreEntry

unfold
let impl_71 = impl_71'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_72': Wasm_bindgen.Describe.t_WasmDescribe t_WStoreEntry

unfold
let impl_72 = impl_72'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_73': Wasm_bindgen.Convert.Traits.t_IntoWasmAbi t_WStoreEntry

unfold
let impl_73 = impl_73'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_74': Wasm_bindgen.Convert.Traits.t_FromWasmAbi t_WStoreEntry

unfold
let impl_74 = impl_74'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_75': Core_models.Convert.t_From Wasm_bindgen.t_JsValue t_WStoreEntry

unfold
let impl_75 = impl_75'

assume
val f_from__impl_75__e_ee_wbg_wstoreentry_new': u32 -> u32

unfold
let f_from__impl_75__e_ee_wbg_wstoreentry_new = f_from__impl_75__e_ee_wbg_wstoreentry_new'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_76': Wasm_bindgen.Convert.Traits.t_RefFromWasmAbi t_WStoreEntry

unfold
let impl_76 = impl_76'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_77': Wasm_bindgen.Convert.Traits.t_RefMutFromWasmAbi t_WStoreEntry

unfold
let impl_77 = impl_77'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_78': Wasm_bindgen.Convert.Traits.t_LongRefFromWasmAbi t_WStoreEntry

unfold
let impl_78 = impl_78'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_79': Wasm_bindgen.Convert.Traits.t_OptionIntoWasmAbi t_WStoreEntry

unfold
let impl_79 = impl_79'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_80': Wasm_bindgen.Convert.Traits.t_OptionFromWasmAbi t_WStoreEntry

unfold
let impl_80 = impl_80'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_81': Wasm_bindgen.Convert.Traits.t_TryFromJsValue t_WStoreEntry

unfold
let impl_81 = impl_81'

assume
val f_try_from_js_value_ref__impl_81__e_ee_wbg_wstoreentry_unwrap': u32 -> u32

unfold
let f_try_from_js_value_ref__impl_81__e_ee_wbg_wstoreentry_unwrap =
  f_try_from_js_value_ref__impl_81__e_ee_wbg_wstoreentry_unwrap'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_82': Wasm_bindgen.Describe.t_WasmDescribeVector t_WStoreEntry

unfold
let impl_82 = impl_82'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_83': Wasm_bindgen.Convert.Traits.t_VectorIntoWasmAbi t_WStoreEntry

unfold
let impl_83 = impl_83'

[@@ FStar.Tactics.Typeclasses.tcinstance]
assume
val impl_84': Wasm_bindgen.Convert.Traits.t_VectorFromWasmAbi t_WStoreEntry

unfold
let impl_84 = impl_84'

/// Build a server store entry from a 16-byte message_id and a WEnvelope.
let impl_WStoreEntry__new (message_id_16_: t_Slice u8) (envelope: t_WEnvelope) : t_WStoreEntry =
  let _:Prims.unit =
    match Core_models.Slice.impl__len #u8 message_id_16_, mk_usize 16 <: (usize & usize) with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let id:t_Array u8 (mk_usize 16) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 16) in
  let id:t_Array u8 (mk_usize 16) = Core_models.Slice.impl__copy_from_slice #u8 id message_id_16_ in
  {
    f_inner
    =
    Securedrop_protocol.Bench.Encrypt_decrypt.impl_ServerMessageStore__new id
      (Core_models.Clone.f_clone #Securedrop_protocol.Bench.Encrypt_decrypt.t_Envelope
          #FStar.Tactics.Typeclasses.solve
          envelope.f_inner
        <:
        Securedrop_protocol.Bench.Encrypt_decrypt.t_Envelope)
  }
  <:
  t_WStoreEntry

assume
val impl_WStoreEntry__new__e_': Prims.unit

unfold
let impl_WStoreEntry__new__e_ = impl_WStoreEntry__new__e_'

/// Build a server store entry from a 16-byte message_id and a WEnvelope.
assume
val impl_WStoreEntry__new__e___e_ee_wasm_bindgen_generated_WStoreEntry_new':
    arg0_1_: u32 ->
    arg0_2_: u32 ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit ->
    arg1_1_: u32 ->
    arg1_2_: Prims.unit ->
    arg1_3_: Prims.unit ->
    arg1_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let impl_WStoreEntry__new__e___e_ee_wasm_bindgen_generated_WStoreEntry_new =
  impl_WStoreEntry__new__e___e_ee_wasm_bindgen_generated_WStoreEntry_new'

assume
val impl_WStoreEntry__new__e___e_ee_wasm_bindgen_generated_WStoreEntry_new__e_': Prims.unit

unfold
let impl_WStoreEntry__new__e___e_ee_wasm_bindgen_generated_WStoreEntry_new__e_ =
  impl_WStoreEntry__new__e___e_ee_wasm_bindgen_generated_WStoreEntry_new__e_'

/// `seed32` must be exactly 32 bytes.
let encrypt_once
      (seed32: t_Slice u8)
      (sender: t_WSource)
      (recipient: t_WJournalist)
      (recipient_bundle_index: usize)
      (plaintext: t_Slice u8)
    : t_WEnvelope =
  let _:Prims.unit =
    match Core_models.Slice.impl__len #u8 seed32, mk_usize 32 <: (usize & usize) with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let seed:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let seed:t_Array u8 (mk_usize 32) = Core_models.Slice.impl__copy_from_slice #u8 seed seed32 in
  let env:Securedrop_protocol.Bench.Encrypt_decrypt.t_Envelope =
    Securedrop_protocol.Bench.Encrypt_decrypt.bench_encrypt seed
      (Rust_primitives.unsize sender.f_inner
        <:
        dyn 1 (fun z -> Securedrop_protocol.Bench.Encrypt_decrypt.t_User z))
      (Rust_primitives.unsize recipient.f_inner
        <:
        dyn 1 (fun z -> Securedrop_protocol.Bench.Encrypt_decrypt.t_User z))
      recipient_bundle_index
      plaintext
  in
  Core_models.Convert.f_into #Securedrop_protocol.Bench.Encrypt_decrypt.t_Envelope
    #t_WEnvelope
    #FStar.Tactics.Typeclasses.solve
    env

assume
val e_': Prims.unit

unfold
let e_ = e_'

/// `seed32` must be exactly 32 bytes.
assume
val e___e_ee_wasm_bindgen_generated_encrypt_once':
    arg0_1_: u32 ->
    arg0_2_: u32 ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit ->
    arg1_1_: u32 ->
    arg1_2_: Prims.unit ->
    arg1_3_: Prims.unit ->
    arg1_4_: Prims.unit ->
    arg2_1_: u32 ->
    arg2_2_: Prims.unit ->
    arg2_3_: Prims.unit ->
    arg2_4_: Prims.unit ->
    arg3_1_: u32 ->
    arg3_2_: Prims.unit ->
    arg3_3_: Prims.unit ->
    arg3_4_: Prims.unit ->
    arg4_1_: u32 ->
    arg4_2_: u32 ->
    arg4_3_: Prims.unit ->
    arg4_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let e___e_ee_wasm_bindgen_generated_encrypt_once = e___e_ee_wasm_bindgen_generated_encrypt_once'

assume
val e___e_ee_wasm_bindgen_generated_encrypt_once__e_': Prims.unit

unfold
let e___e_ee_wasm_bindgen_generated_encrypt_once__e_ =
  e___e_ee_wasm_bindgen_generated_encrypt_once__e_'

/// Returns plaintext bytes.
let decrypt_once (recipient: t_WJournalist) (envelope: t_WEnvelope)
    : Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global =
  let (pt: Securedrop_protocol.Bench.Encrypt_decrypt.t_Plaintext):Securedrop_protocol.Bench.Encrypt_decrypt.t_Plaintext
  =
    Securedrop_protocol.Bench.Encrypt_decrypt.bench_decrypt (Rust_primitives.unsize recipient
            .f_inner
        <:
        dyn 1 (fun z -> Securedrop_protocol.Bench.Encrypt_decrypt.t_User z))
      envelope.f_inner
  in
  Securedrop_protocol.Bench.Encrypt_decrypt.impl_Plaintext__into_bytes pt

assume
val e_ee_1': Prims.unit

unfold
let e_ee_1 = e_ee_1'

/// Returns plaintext bytes.
assume
val e_ee_1__e_ee_wasm_bindgen_generated_decrypt_once':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit ->
    arg1_1_: u32 ->
    arg1_2_: Prims.unit ->
    arg1_3_: Prims.unit ->
    arg1_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet Wasm_bindgen.Convert.Slices.t_WasmSlice

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_decrypt_once =
  e_ee_1__e_ee_wasm_bindgen_generated_decrypt_once'

assume
val e_ee_1__e_ee_wasm_bindgen_generated_decrypt_once__e_': Prims.unit

unfold
let e_ee_1__e_ee_wasm_bindgen_generated_decrypt_once__e_ =
  e_ee_1__e_ee_wasm_bindgen_generated_decrypt_once__e_'

/// Build challenges for fetch
let compute_fetch_challenges_once
      (seed32: t_Slice u8)
      (entries: Alloc.Boxed.t_Box (t_Slice t_WStoreEntry) Alloc.Alloc.t_Global)
      (total_responses: usize)
    : Alloc.Boxed.t_Box (t_Slice t_WFetchResponse) Alloc.Alloc.t_Global =
  let _:Prims.unit =
    match Core_models.Slice.impl__len #u8 seed32, mk_usize 32 <: (usize & usize) with
    | left_val, right_val -> Hax_lib.v_assert (left_val =. right_val <: bool)
  in
  let seed:t_Array u8 (mk_usize 32) = Rust_primitives.Hax.repeat (mk_u8 0) (mk_usize 32) in
  let seed:t_Array u8 (mk_usize 32) = Core_models.Slice.impl__copy_from_slice #u8 seed seed32 in
  let rng:Rand_chacha.Chacha.t_ChaCha20Rng = rng_from_seed seed in
  let
  (store:
    Alloc.Vec.t_Vec Securedrop_protocol.Bench.Encrypt_decrypt.t_ServerMessageStore
      Alloc.Alloc.t_Global):Alloc.Vec.t_Vec
    Securedrop_protocol.Bench.Encrypt_decrypt.t_ServerMessageStore Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_collect #(Core_models.Iter.Adapters.Map.t_Map
          (Alloc.Vec.Into_iter.t_IntoIter t_WStoreEntry Alloc.Alloc.t_Global)
          (t_WStoreEntry -> Securedrop_protocol.Bench.Encrypt_decrypt.t_ServerMessageStore))
      #FStar.Tactics.Typeclasses.solve
      #(Alloc.Vec.t_Vec Securedrop_protocol.Bench.Encrypt_decrypt.t_ServerMessageStore
          Alloc.Alloc.t_Global)
      (Core_models.Iter.Traits.Iterator.f_map #(Alloc.Vec.Into_iter.t_IntoIter t_WStoreEntry
              Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #Securedrop_protocol.Bench.Encrypt_decrypt.t_ServerMessageStore
          (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec t_WStoreEntry
                  Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              (Alloc.Slice.impl__into_vec #t_WStoreEntry #Alloc.Alloc.t_Global entries
                <:
                Alloc.Vec.t_Vec t_WStoreEntry Alloc.Alloc.t_Global)
            <:
            Alloc.Vec.Into_iter.t_IntoIter t_WStoreEntry Alloc.Alloc.t_Global)
          (fun w ->
              let w:t_WStoreEntry = w in
              w.f_inner)
        <:
        Core_models.Iter.Adapters.Map.t_Map
          (Alloc.Vec.Into_iter.t_IntoIter t_WStoreEntry Alloc.Alloc.t_Global)
          (t_WStoreEntry -> Securedrop_protocol.Bench.Encrypt_decrypt.t_ServerMessageStore))
  in
  let
  (tmp0: Rand_chacha.Chacha.t_ChaCha20Rng),
  (out:
    Alloc.Vec.t_Vec Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse Alloc.Alloc.t_Global)
  =
    Securedrop_protocol.Bench.Encrypt_decrypt.compute_fetch_challenges #Rand_chacha.Chacha.t_ChaCha20Rng
      rng
      (Core_models.Ops.Deref.f_deref #(Alloc.Vec.t_Vec
              Securedrop_protocol.Bench.Encrypt_decrypt.t_ServerMessageStore Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          store
        <:
        t_Slice Securedrop_protocol.Bench.Encrypt_decrypt.t_ServerMessageStore)
      total_responses
  in
  let rng:Rand_chacha.Chacha.t_ChaCha20Rng = tmp0 in
  Alloc.Vec.impl_1__into_boxed_slice #t_WFetchResponse
    #Alloc.Alloc.t_Global
    (Core_models.Iter.Traits.Iterator.f_collect #(Core_models.Iter.Adapters.Map.t_Map
            (Alloc.Vec.Into_iter.t_IntoIter
                Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse Alloc.Alloc.t_Global)
            (Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse -> t_WFetchResponse))
        #FStar.Tactics.Typeclasses.solve
        #(Alloc.Vec.t_Vec t_WFetchResponse Alloc.Alloc.t_Global)
        (Core_models.Iter.Traits.Iterator.f_map #(Alloc.Vec.Into_iter.t_IntoIter
                Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse Alloc.Alloc.t_Global)
            #FStar.Tactics.Typeclasses.solve
            #t_WFetchResponse
            (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec
                    Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse Alloc.Alloc.t_Global)
                #FStar.Tactics.Typeclasses.solve
                out
              <:
              Alloc.Vec.Into_iter.t_IntoIter
                Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse Alloc.Alloc.t_Global)
            Core_models.Convert.f_from
          <:
          Core_models.Iter.Adapters.Map.t_Map
            (Alloc.Vec.Into_iter.t_IntoIter
                Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse Alloc.Alloc.t_Global)
            (Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse -> t_WFetchResponse))
      <:
      Alloc.Vec.t_Vec t_WFetchResponse Alloc.Alloc.t_Global)

assume
val e_ee_2': Prims.unit

unfold
let e_ee_2 = e_ee_2'

/// Build challenges for fetch
assume
val e_ee_2__e_ee_wasm_bindgen_generated_compute_fetch_challenges_once':
    arg0_1_: u32 ->
    arg0_2_: u32 ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit ->
    arg1_1_: u32 ->
    arg1_2_: u32 ->
    arg1_3_: Prims.unit ->
    arg1_4_: Prims.unit ->
    arg2_1_: u32 ->
    arg2_2_: Prims.unit ->
    arg2_3_: Prims.unit ->
    arg2_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet Wasm_bindgen.Convert.Slices.t_WasmSlice

unfold
let e_ee_2__e_ee_wasm_bindgen_generated_compute_fetch_challenges_once =
  e_ee_2__e_ee_wasm_bindgen_generated_compute_fetch_challenges_once'

assume
val e_ee_2__e_ee_wasm_bindgen_generated_compute_fetch_challenges_once__e_': Prims.unit

unfold
let e_ee_2__e_ee_wasm_bindgen_generated_compute_fetch_challenges_once__e_ =
  e_ee_2__e_ee_wasm_bindgen_generated_compute_fetch_challenges_once__e_'

let fetch_once
      (recipient: t_WJournalist)
      (challenges: Alloc.Boxed.t_Box (t_Slice t_WFetchResponse) Alloc.Alloc.t_Global)
    : Js_sys.t_Array =
  let
  (inner:
    Alloc.Vec.t_Vec Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse Alloc.Alloc.t_Global):Alloc.Vec.t_Vec
    Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse Alloc.Alloc.t_Global =
    Core_models.Iter.Traits.Iterator.f_collect #(Core_models.Iter.Adapters.Map.t_Map
          (Alloc.Vec.Into_iter.t_IntoIter t_WFetchResponse Alloc.Alloc.t_Global)
          (t_WFetchResponse -> Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse))
      #FStar.Tactics.Typeclasses.solve
      #(Alloc.Vec.t_Vec Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse
          Alloc.Alloc.t_Global)
      (Core_models.Iter.Traits.Iterator.f_map #(Alloc.Vec.Into_iter.t_IntoIter t_WFetchResponse
              Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          #Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse
          (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec t_WFetchResponse
                  Alloc.Alloc.t_Global)
              #FStar.Tactics.Typeclasses.solve
              (Alloc.Slice.impl__into_vec #t_WFetchResponse #Alloc.Alloc.t_Global challenges
                <:
                Alloc.Vec.t_Vec t_WFetchResponse Alloc.Alloc.t_Global)
            <:
            Alloc.Vec.Into_iter.t_IntoIter t_WFetchResponse Alloc.Alloc.t_Global)
          (fun w ->
              let w:t_WFetchResponse = w in
              w.f_inner)
        <:
        Core_models.Iter.Adapters.Map.t_Map
          (Alloc.Vec.Into_iter.t_IntoIter t_WFetchResponse Alloc.Alloc.t_Global)
          (t_WFetchResponse -> Securedrop_protocol.Bench.Encrypt_decrypt.t_FetchResponse))
  in
  let (ids: Alloc.Vec.t_Vec (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global):Alloc.Vec.t_Vec
    (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global =
    Securedrop_protocol.Bench.Encrypt_decrypt.bench_fetch (Rust_primitives.unsize recipient.f_inner
        <:
        dyn 1 (fun z -> Securedrop_protocol.Bench.Encrypt_decrypt.t_User z))
      inner
  in
  let out:Js_sys.t_Array = Js_sys.impl_Array__new () in
  let _:Prims.unit =
    Core_models.Iter.Traits.Iterator.f_fold (Core_models.Iter.Traits.Collect.f_into_iter #(Alloc.Vec.t_Vec
              (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global) Alloc.Alloc.t_Global)
          #FStar.Tactics.Typeclasses.solve
          ids
        <:
        Alloc.Vec.Into_iter.t_IntoIter (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
          Alloc.Alloc.t_Global)
      ()
      (fun temp_0_ id ->
          let _:Prims.unit = temp_0_ in
          let id:Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global = id in
          let u8arr:Js_sys.t_Uint8Array =
            Core_models.Convert.f_from #Js_sys.t_Uint8Array
              #(t_Slice u8)
              #FStar.Tactics.Typeclasses.solve
              (Alloc.Vec.impl_1__as_slice #u8 #Alloc.Alloc.t_Global id <: t_Slice u8)
          in
          let _:u32 =
            Js_sys.impl_Array__push out
              (Core_models.Convert.f_into #Js_sys.t_Uint8Array
                  #Wasm_bindgen.t_JsValue
                  #FStar.Tactics.Typeclasses.solve
                  u8arr
                <:
                Wasm_bindgen.t_JsValue)
          in
          ())
  in
  out

assume
val e_ee_3': Prims.unit

unfold
let e_ee_3 = e_ee_3'

assume
val e_ee_3__e_ee_wasm_bindgen_generated_fetch_once':
    arg0_1_: u32 ->
    arg0_2_: Prims.unit ->
    arg0_3_: Prims.unit ->
    arg0_4_: Prims.unit ->
    arg1_1_: u32 ->
    arg1_2_: u32 ->
    arg1_3_: Prims.unit ->
    arg1_4_: Prims.unit
  -> Wasm_bindgen.Convert.Traits.t_WasmRet u32

unfold
let e_ee_3__e_ee_wasm_bindgen_generated_fetch_once = e_ee_3__e_ee_wasm_bindgen_generated_fetch_once'

assume
val e_ee_3__e_ee_wasm_bindgen_generated_fetch_once__e_': Prims.unit

unfold
let e_ee_3__e_ee_wasm_bindgen_generated_fetch_once__e_ =
  e_ee_3__e_ee_wasm_bindgen_generated_fetch_once__e_'
