use registry::registry_service_client::RegistryServiceClient;
use std::collections::HashMap;

#[path = "gen/registry_api.v1.rs"]
pub mod registry;

const DID_METHOD: &'static str = "knox";

pub struct RegistryResolver {
    url: String,
}

impl RegistryResolver {
    pub async fn new(url: String) -> Self {
        return Self { url };
    }

    const fn get_method_helper() -> &'static str {
        return DID_METHOD;
    }
}
#[async_trait::async_trait]
impl ssi::DIDResolver for RegistryResolver {
    fn get_method() -> String {
        return String::from(Self::get_method_helper());
    }

    async fn create(
        self: &RegistryResolver,
        did: String,
        document: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut client = RegistryServiceClient::connect(self.url.clone())
            .await
            .unwrap();
        let document: HashMap<String, pbjson_types::Value> =
            serde_json::from_value(document).unwrap();
        client
            .create(registry::CreateRequest {
                did,
                document: Some(document.into()),
            })
            .await
            .unwrap();
        Ok(())
    }

    async fn read(&self, did: String) -> serde_json::Value {
        let mut client = RegistryServiceClient::connect(self.url.clone())
            .await
            .unwrap();
        let res = client.read(registry::ReadRequest { did }).await.unwrap();
        let document =
            serde_json::to_value(res.into_inner().document.unwrap_or_default()).unwrap_or_default();

        return document;
    }
}

#[cfg(test)]
mod tests {
    use crate::DID_METHOD;

    #[test]
    fn test_create() -> Result<(), String> {
        assert!(false);
        Ok(())
    }

    #[test]
    fn test_read() -> Result<(), String> {
        assert!(false);
        Ok(())
    }

    #[test]
    fn test_get_method() -> Result<(), String> {
        assert_eq!(DID_METHOD, "knox");
        Ok(())
    }
}
