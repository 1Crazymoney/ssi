use serde::{self, Deserialize, Deserializer, Serializer};

pub fn serialize<S>(cr_type: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.collect_seq(cr_type.split(","))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let s = Vec::<String>::deserialize(deserializer)?.join(",");
    Ok(s)
}
