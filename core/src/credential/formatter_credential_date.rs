use chrono::{DateTime, Utc};
use serde::{self, Deserialize, Deserializer, Serializer};
use std::string::String;
use std::time::SystemTime;

const FORMAT: &'static str = "%Y-%m-%dT%H:%M:%SZ";

pub fn serialize<S>(date: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let utc = DateTime::<Utc>::from(*date).format(FORMAT);
    serializer.serialize_str(&format!("{utc}"))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    String::deserialize(deserializer) // -> Result<String, _>
        .and_then(|s: String| DateTime::parse_from_rfc3339(&s).map_err(Error::custom))
        .map(SystemTime::from)
}
