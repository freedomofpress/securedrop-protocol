use serde::{Deserialize, Serialize};

use crate::sign::VerifyingKey;
use crate::wire::bundle::SignedLongtermKeyBundle;

#[derive(Clone, Debug)]
#[cfg_attr(not(hax), derive(Serialize, Deserialize))]
pub struct Enrollment {
    pub bundle: SignedLongtermKeyBundle,
    // Journalist's long-term verification key, verified out of band.
    pub verification_key: VerifyingKey,
}
