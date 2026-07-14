use securedrop_protocol_minimal::{JournalistPublic, JournalistPublicView, Source, UserPublic};
use serde::{
    Serialize,
    ser::{SerializeStruct, Serializer},
};

pub struct JournalistPretty(pub JournalistPublicView);

impl Serialize for JournalistPretty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let j = &self.0;
        let mut s = serializer.serialize_struct("Journalist", 4)?;

        s.serialize_field("vk", &j.verifying_key().into_bytes())?;
        s.serialize_field("fetch", &j.fetch_pk().into_bytes())?;
        s.serialize_field("apke_longterm", &j.message_auth_pk().as_bytes())?;

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
