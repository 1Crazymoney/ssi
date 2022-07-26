use serde::{self, Deserialize, Deserializer, Serializer};
use std::string::String;

pub fn serialize<S>(ctx: &Vec<String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ctx_vec = crate::CONTEXT_CREDENTIALS
        .into_iter()
        .map(|s| s.to_string());
    serializer.collect_seq(ctx_vec)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Vec::<String>::deserialize(deserializer)?;
    let s = crate::CONTEXT_CREDENTIALS
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    Ok(s)
}
