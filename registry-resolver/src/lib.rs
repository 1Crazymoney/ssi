mod registry_client;
const DID_METHOD: &'static str = "knox";
use registry_client::GrpcClient;

pub struct RegistryResolver {
    client: Box<dyn registry_client::RegistryClient + Send + Sync>,
}

impl RegistryResolver {
    pub async fn new(url: impl Into<String>) -> Self {
        let client = GrpcClient::new(url.into()).await;
        return Self {
            client: Box::new(client),
        };
    }

    const fn get_method_helper() -> &'static str {
        return DID_METHOD;
    }
}
#[async_trait::async_trait]
impl ssi::DIDResolver for RegistryResolver {
    fn get_method() -> &'static str {
        return Self::get_method_helper();
    }

    async fn create(
        self,
        did: String,
        document: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let document: pbjson_types::Struct = serde_json::from_value(document)?;
        self.client.create(did, Some(document)).await?;

        Ok(())
    }

    async fn read(self, did: String) -> serde_json::Value {
        let res = self.client.read(did).await.unwrap();
        let document =
            serde_json::to_value(res.into_inner().document.unwrap_or_default()).unwrap_or_default();

        return document;
    }
}

#[cfg(test)]
mod tests {
    use ssi::DIDResolver;

    use crate::{
        registry_client::registry::CreateResponse, registry_client::MockRegistryClient,
        RegistryResolver,
    };

    fn create_did_doc(did: String) -> serde_json::Value {
        return serde_json::json!({
                "@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/ed25519-2020/v1"],
                "id":did,
                "authentication":[
                    {"id":format!("did:knox:{}#{}", did, did),"type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }],
                "capabilityInvocation":[
                    {"id":format!("did:knox:{}#{}", did, did),"type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }],
                "capabilityDelegation":[
                    {"id":format!("did:knox:{}#{}", did, did),"type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }],
                "assertionMethod":[
                    {"id":format!("did:knox:{}#{}", did, did),"type":"Ed25519VerificationKey2020","controller":"did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh","publicKeyMultibase":"z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh"
                }]
            }
        );
    }

    fn create_did_struct(doc: serde_json::Value) -> pbjson_types::Struct {
        return serde_json::from_value(doc).unwrap();
    }

    fn create_did() -> String {
        return String::from("did:knox:z6MkfFmsob7fC3MmqU1JVfdBnMbnAw7xm1mrEtPvAoojLcRh");
    }

    #[rstest::rstest]
    #[case::network_failure(
        create_did(),
        create_did_doc(create_did()),
        Some(Err(tonic::Status::invalid_argument("message"))),
        false
    )]
    #[case::success(
        create_did(),
        create_did_doc(create_did()),
        Some(Ok(tonic::Response::new(CreateResponse {}))),
        true
    )]
    #[case::parsing_failure(
        create_did(),
        serde_json::json!("{}"),
        None,
        false
    )]
    async fn test_create(
        #[case] did: String,
        #[case] doc: serde_json::Value,
        #[case] mock_create_response: Option<
            Result<tonic::Response<CreateResponse>, tonic::Status>,
        >,
        #[case] expect_ok: bool,
    ) {
        let mut mock_client = MockRegistryClient::default();
        if mock_create_response.is_some() {
            mock_client
                .expect_create()
                .with(
                    mockall::predicate::eq(did.clone()),
                    mockall::predicate::eq(Some(create_did_struct(doc.clone()))),
                )
                .return_once(|_, _| (mock_create_response.unwrap()));
        }

        let resolver = RegistryResolver {
            client: Box::new(mock_client),
        };

        let res = resolver.create(did, doc).await;
        assert_eq!(res.is_ok(), expect_ok);
    }

    #[test]
    fn test_read() -> Result<(), String> {
        assert!(false);
        Ok(())
    }

    #[test]
    fn test_get_method() -> Result<(), String> {
        assert_eq!(RegistryResolver::get_method(), "knox");
        Ok(())
    }

    #[test]
    fn test_create_verification_method() -> Result<(), String> {
        let did = String::from("12345");
        let key_id = String::from("123456");
        assert_eq!(
            RegistryResolver::create_verification_method(did, key_id),
            "did:knox:12345#123456"
        );
        Ok(())
    }
}
