pub fn normalize(doc: serde_json::Value) -> impl AsRef<[u8]> {
    let encoded = doc.to_string();
    let result = encoded.into_bytes();
    return result;
}
