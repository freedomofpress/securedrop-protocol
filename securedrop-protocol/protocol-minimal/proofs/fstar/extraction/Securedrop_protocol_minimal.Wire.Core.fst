module Securedrop_protocol_minimal.Wire.Core
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

include Securedrop_protocol_minimal.Bundle {t_JournalistLongTermView as t_JournalistLongTermView}

include Securedrop_protocol_minimal.Bundle {t_WelcomeBundle as t_WelcomeBundle}

include Securedrop_protocol_minimal.Bundle {t_JournalistEphemeralKeys as t_JournalistEphemeralKeys}

include Securedrop_protocol_minimal.Bundle {t_MessageChallengeFetchRequest as t_MessageChallengeFetchRequest}

include Securedrop_protocol_minimal.Bundle {MessageChallengeFetchRequest as MessageChallengeFetchRequest}

include Securedrop_protocol_minimal.Bundle {t_MessageChallengeFetchResponse as t_MessageChallengeFetchResponse}

include Securedrop_protocol_minimal.Bundle {t_MessageFetchRequest as t_MessageFetchRequest}

include Securedrop_protocol_minimal.Bundle {t_FetchResponse as t_FetchResponse}

include Securedrop_protocol_minimal.Bundle {impl_2 as impl_2}

include Securedrop_protocol_minimal.Bundle {impl_3 as impl_3}

include Securedrop_protocol_minimal.Bundle {impl__new as impl_FetchResponse__new}

include Securedrop_protocol_minimal.Bundle {t_Envelope as t_Envelope}

include Securedrop_protocol_minimal.Bundle {impl_4 as impl_4}

include Securedrop_protocol_minimal.Bundle {impl_5 as impl_5}

include Securedrop_protocol_minimal.Bundle {impl_1__size_hint as impl_Envelope__size_hint}

include Securedrop_protocol_minimal.Bundle {impl_1__cmessage_len as impl_Envelope__cmessage_len}

include Securedrop_protocol_minimal.Bundle {impl_1__cmetadata_len as impl_Envelope__cmetadata_len}

include Securedrop_protocol_minimal.Bundle {impl_1__to_challenges as impl_Envelope__to_challenges}
