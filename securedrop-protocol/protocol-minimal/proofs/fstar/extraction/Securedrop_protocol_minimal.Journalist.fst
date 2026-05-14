module Securedrop_protocol_minimal.Journalist
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

include Securedrop_protocol_minimal.Bundle {t_Journalist as t_Journalist}

include Securedrop_protocol_minimal.Bundle {t_JournalistPublicView as t_JournalistPublicView}

include Securedrop_protocol_minimal.Bundle {impl__new as impl_JournalistPublicView__new}

include Securedrop_protocol_minimal.Bundle {impl_1__from__journalist as impl_1}

include Securedrop_protocol_minimal.Bundle {impl_2 as impl_2}

include Securedrop_protocol_minimal.Bundle {impl_3 as impl_3}

include Securedrop_protocol_minimal.Bundle {impl_4 as impl_4}

include Securedrop_protocol_minimal.Bundle {impl_5 as impl_5}

include Securedrop_protocol_minimal.Bundle {f_signed_keybundles__impl_5__extract_public_bundle as f_signed_keybundles__impl_5__extract_public_bundle}

include Securedrop_protocol_minimal.Bundle {impl_6__new as impl_Journalist__new}

include Securedrop_protocol_minimal.Bundle {impl_6__public as impl_Journalist__public}
