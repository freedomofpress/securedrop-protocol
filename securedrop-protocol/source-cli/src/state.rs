use securedrop_protocol_minimal::{
    JournalistPublic, JournalistPublicView, Source, UserPublic, UserSecret,
};
use serde::{
    Serialize,
    ser::{SerializeStruct, Serializer},
};

pub struct JournalistPretty(pub JournalistPublicView);

pub(crate) fn serialize_long_key(bytes: &Vec<u8>) -> String {
    if bytes.len() <= 32 {
        hex::encode(bytes)
    } else {
        let first = hex::encode(&bytes[..16]);
        let last = hex::encode(&bytes[bytes.len() - 16..]);
        format!("{}...{}", first, last)
    }
}

impl Serialize for JournalistPretty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let j = &self.0;
        let mut s = serializer.serialize_struct("Journalist", 4)?;

        s.serialize_field("vk", &hex::encode(&j.verifying_key().into_bytes()))?;
        s.serialize_field("fetch", &hex::encode(&j.fetch_pk().into_bytes()))?;

        let apke = serialize_long_key(&j.message_auth_pk().as_bytes());
        s.serialize_field("apke_longterm_pk", &apke)?;

        let md = serialize_long_key(&j.message_metadata_pk().as_bytes().to_vec());
        s.serialize_field("metadata_pk", &md)?;

        s.end()
    }
}

pub struct SourcePretty(pub Source);

impl Serialize for SourcePretty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let source = &self.0;
        let mut s = serializer.serialize_struct("Source", 4)?;

        s.serialize_field("passphrase", &source.passphrase())?;

        let apke = serialize_long_key(&source.own_message_auth_pk().as_bytes());
        s.serialize_field("apke_longterm_pk", &apke)?;
        s.serialize_field(
            "fetch pk",
            &hex::encode(&source.fetch_keypair().1.into_bytes()),
        )?;

        s.end()
    }
}

#[derive(Default, Serialize)]
pub struct State {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fpf_vk: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourcePretty>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_phrase: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<JournalistPretty>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub replies: Vec<String>,
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn show_state(&self) -> anyhow::Result<()> {
        println!("{}", serde_json::to_string_pretty(self)?);
        Ok(())
    }
}
