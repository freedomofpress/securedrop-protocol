module Securedrop_protocol_minimal.Server.Challenge
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

include Securedrop_protocol_minimal.Bundle {sort_by_id as sort_by_id}

include Securedrop_protocol_minimal.Bundle {t_Challenges as t_Challenges}

include Securedrop_protocol_minimal.Bundle {compute_fetch_challenges as compute_fetch_challenges}

include Securedrop_protocol_minimal.Bundle {make_response as make_response}
