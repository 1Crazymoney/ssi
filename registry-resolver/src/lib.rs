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
    ) -> Result<(), ssi::error::ResolverError> {
        let document: pbjson_types::Struct = serde_json::from_value(document).map_err(|e| {
            ssi::error::ResolverError::new(e.to_string(), ssi::error::ErrorKind::InvalidData)
        })?;

        self.client.create(did, Some(document)).await.map_err(|e| {
            ssi::error::ResolverError::new(e.to_string(), ssi::error::ErrorKind::NetworkFailure)
        })?;

        Ok(())
    }

    async fn read(self, did: String) -> Result<serde_json::Value, ssi::error::ResolverError> {
        let res = self.client.read(did).await.map_err(|e| {
            ssi::error::ResolverError::new(e.to_string(), ssi::error::ErrorKind::NetworkFailure)
        })?;

        let document = res.into_inner().document;

        match document {
            Some(document) => Ok(serde_json::to_value(document).map_err(|e| {
                ssi::error::ResolverError::new(e.to_string(), ssi::error::ErrorKind::InvalidData)
            })?),
            None => Err(ssi::error::ResolverError::new(
                "Document not found",
                ssi::error::ErrorKind::DocumentNotFound,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use ssi::DIDResolver;

    use crate::{
        registry_client::{registry::CreateResponse, registry::ReadResponse, MockRegistryClient},
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
        Some(ssi::error::ErrorKind::NetworkFailure),
        false
    )]
    #[case::success(
        create_did(),
        create_did_doc(create_did()),
        Some(Ok(tonic::Response::new(CreateResponse {}))),
        None,
        true
    )]
    #[case::parsing_failure(
        create_did(),
        serde_json::json!("{}"),
        None,
        Some(ssi::error::ErrorKind::InvalidData),
        false
    )]
    async fn test_create(
        #[case] did: String,
        #[case] doc: serde_json::Value,
        #[case] mock_create_response: Option<
            Result<tonic::Response<CreateResponse>, tonic::Status>,
        >,
        #[case] expect_error_kind: Option<ssi::error::ErrorKind>,
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
        match res.err() {
            Some(e) => assert_eq!(e.kind, expect_error_kind.unwrap()),
            None => assert!(expect_error_kind.is_none()),
        }
    }

    #[rstest::rstest]
    #[case::network_failure(
        create_did(),
        Some(Err(tonic::Status::invalid_argument("message"))),
        Some(ssi::error::ErrorKind::NetworkFailure),
        false
    )]
    #[case::success(
        create_did(),
        Some(Ok(tonic::Response::new(ReadResponse {
            did: create_did(),
            document: Some(create_did_struct(create_did_doc(create_did()))),
            metadata: None,
         }))),
        None,
        true
    )]
    #[case::no_document(
        create_did(),
        Some(Ok(tonic::Response::new(ReadResponse {
            did: create_did(),
            document: None,
            metadata: None,
         }))),
        Some(ssi::error::ErrorKind::DocumentNotFound),
        false
    )]
    async fn test_read(
        #[case] did: String,
        #[case] mock_read_response: Option<Result<tonic::Response<ReadResponse>, tonic::Status>>,
        #[case] expect_error_kind: Option<ssi::error::ErrorKind>,
        #[case] expect_ok: bool,
    ) {
        let mut mock_client = MockRegistryClient::default();
        if mock_read_response.is_some() {
            mock_client
                .expect_read()
                .with(mockall::predicate::eq(did.clone()))
                .return_once(|_| (mock_read_response.unwrap()));
        }

        let resolver = RegistryResolver {
            client: Box::new(mock_client),
        };

        let res = resolver.read(did).await;
        assert_eq!(res.is_ok(), expect_ok);
        match res.err() {
            Some(e) => assert_eq!(e.kind, expect_error_kind.unwrap()),
            None => assert!(expect_error_kind.is_none()),
        }
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
