#![allow(unused_variables)]
#![allow(dead_code)]
use std::time::SystemTime;

use crate::HashMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod formatter_context;
mod formatter_credential_date;
mod formatter_credential_type;

// cred_subject is a generic that implements trait X
// trait X allows us to encode that object into JSON-LD
// We provide types that implement trait X for the cred types that we support
// Users can also user their own types that implement trait X if they need a different structure
// ---
// Default context and Cred types are defaulted but can be redefined

type VerificationContext = [&'static str; 2];

pub const CONTEXT_CREDENTIALS: VerificationContext = [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1",
];

pub const CRED_TYPE_PERMANENT_RESIDENT_CARD: &'static str = "PermanentResidentCard";
pub const CRED_TYPE_BANK_CARD: &'static str = "BankCard";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CredentialSubject {
    id: String,
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifiableCredential {
    #[serde(flatten)]
    credential: Credential,
    pub proof: crate::proof::DataIntegrityProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credential {
    #[serde(rename = "@context")]
    #[serde(with = "formatter_context")]
    context: Vec<String>,

    #[serde(rename = "@id")]
    id: String,

    #[serde(rename = "type")]
    cred_type: Vec<String>,

    #[serde(rename = "issuanceDate")]
    #[serde(with = "formatter_credential_date")]
    issuance_date: SystemTime,

    #[serde(rename = "credentialSubject")]
    subject: CredentialSubject,
    #[serde(flatten)]
    pub property_set: HashMap<String, Value>,
}

impl Credential {
    pub fn new(
        context: VerificationContext,
        cred_type: Vec<String>,
        cred_subject: HashMap<String, Value>,
        property_set: HashMap<String, Value>,
        id: &str,
    ) -> Credential {
        let vc = Credential {
            context: context.into_iter().map(|s| s.to_string()).collect(),
            id: id.to_string(),
            cred_type: cred_type,
            issuance_date: SystemTime::now(),
            subject: CredentialSubject {
                id: id.to_string(),
                property_set: cred_subject,
            },
            property_set: property_set,
        };
        vc
    }

    pub fn serialize(&self) -> Value {
        return serde_json::to_value(&self).unwrap();
    }

    pub fn deserialize(contents: String) -> Result<Credential, serde_json::Error> {
        serde_json::from_str(&contents)
    }

    pub fn create_verifiable_credentials(
        self,
        integrity_proof: crate::proof::DataIntegrityProof,
    ) -> VerifiableCredential {
        let vc = VerifiableCredential {
            credential: self,
            proof: integrity_proof,
        };
        return vc;
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct VerifiablePresentation {
    #[serde(flatten)]
    presentation: Presentation,
    proof: crate::proof::DataIntegrityProof,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct Presentation {
    #[serde(rename = "@context")]
    pub context: VerificationContext,
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,
}

impl Presentation {
    pub fn new(
        context: VerificationContext,
        verifiable_credential: Vec<VerifiableCredential>,
    ) -> Presentation {
        Presentation {
            context,
            verifiable_credential,
        }
    }

    pub fn serialize(&self) -> Value {
        return serde_json::to_value(&self).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::Credential;
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    #[test]
    fn test_create_credential_from_string() -> Result<(), String> {
        let expect = json!({
            "@context":["https://www.w3.org/2018/credentials/v1","https://www.w3.org/2018/credentials/examples/v1"],"@id":"https://issuer.oidp.uscis.gov/credentials/83627465","type":["VerifiableCredential", "PermanentResidentCard"],"issuer": "did:example:28394728934792387",
            "identifier": "83627465",
            "name": "Permanent Resident Card",
            "description": "Government of Example Permanent Resident Card.",
            "issuanceDate": "2019-12-03T12:19:52Z",
            "expirationDate": "2029-12-03T12:19:52Z",
            "credentialSubject": {
            "id": "did:example:b34ca6cd37bbf23",
            "type": ["PermanentResident", "Person"],
            "givenName": "JOHN",
            "familyName": "SMITH",
            "gender": "Male",
            "image": "data:image/png;base64,iVBORw0KGgo...kJggg==",
            "residentSince": "2015-01-01",
            "lprCategory": "C09",
            "lprNumber": "999-999-999",
            "commuterClassification": "C1",
            "birthCountry": "Bahamas",
            "birthDate": "1958-07-17"
            },
        });

        let ds = Credential::deserialize(expect.to_string());
        if ds.is_ok() {
            let vc = ds.unwrap().serialize();
            assert_json_eq!(expect, vc);
        } else {
            assert!(false);
        }
        Ok(())
    }
}
