/// Verification of Data Integrity Proofs requires the resolution of the `verificationMethod` specified in the proof.
/// The `verificationMethod` refers to a cryptographic key stored in some external source.
/// The DIDResolver is responsible for resolving the `verificationMethod` to a key that can be used to verify the proof.
#[async_trait::async_trait]
pub trait DIDResolver {
    /// Given a `did`, resolve the full DID document associated with that matching `did`.
    /// Return the JSON-LD document representing the DID.
    async fn read(&self, did: String) -> serde_json::Value;
    /// Given a `did` and the associated DID Document, register the DID Document with the external source used by the DIDResolver.
    async fn create(
        &self,
        did: String,
        doc: serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>>;
    // Returns the DID Method that the DID Resolver is compatible with. Each resolver can only be compatible with one.
    fn get_method() -> String;
    // Given a `did` and `key` it will construct the proper `verificationMethod` to use as part of the data integrity proof creation process.
    fn create_verification_method(did: String, key_id: String) -> String {
        return format!("{}:{}#{}", did, Self::get_method(), key_id);
    }
}

/// Given the credential type and the credential subject information, create a unissued JSON-LD credential.
/// In order to become a Verifiable Credential, a data integrity proof must be created for the credential and appended to the JSON-LD document.
pub fn create_credential(
    _cred_type: &str,
    _cred_subject: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    unimplemented!();
}

/// Given the set of credentials, create a unsigned JSON-LD Presentation of those credentials.
/// In order to become a Verifiable Presentation, a data integrity proof must be created for the presentation and appended to the JSON-LD document.
pub fn create_presentation(
    _creds: Vec<serde_json::Value>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    unimplemented!();
}

// ed25519 cryptography key generation & DID Document creation
pub fn create_identity(
    _mnemonic: &str,
    _password: Option<String>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    unimplemented!();
}

/// Given a JSON-LD document, create a data integrity proof for the document.
/// Currently, only `Ed25519Signature2018` data integrity proofs in the JSON-LD format can be created.
pub fn create_data_integrity_proof<S: signature::Signature>(
    _doc: serde_json::Value,
    _signer: &impl signature::Signer<S>,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    unimplemented!();
}

/// Given a JSON-LD document and a DIDResolver, verify the data integrity proof for the document.
/// This will by parsing the `verificationMethod` property of the data integrity proof and resolving it to a key that can be used to verify the proof.
/// Currently only `Ed25519Signature2018` is supported for data integrity proof verification.
pub fn verify_data_integrity_proof<S: signature::Signature>(
    _doc: serde_json::Value,
    _resolver: &impl DIDResolver,
    _verifier: &impl signature::Verifier<S>,
) -> Result<bool, Box<dyn std::error::Error>> {
    unimplemented!();
}

/// Given a JSON-LD document and a DIDResolver, verify the data integrity proof for the Verifiable Presentation.
/// Then each claimed Verifiable Credential must be verified for validity and ownership of the credential by the subject.
pub fn verify_presentation<S: signature::Signature>(
    _doc: serde_json::Value,
    _resolver: &impl DIDResolver,
    _verifier: &impl signature::Verifier<S>,
) -> Result<bool, Box<dyn std::error::Error>> {
    unimplemented!();
}
