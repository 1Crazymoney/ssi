use crate::error::SignatureError;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum VerificationRelation {
    AssertionMethod,
    Authentication,
    CapabilityInvocation,
    CapabilityDelegation,
}

pub const PROOF_TYPE: &str = "Ed25519Signature2018";

#[derive(Debug, PartialEq, Clone)]
pub struct Ed25519Signature(pub Vec<u8>);

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub trait Signature: AsRef<[u8]> + core::fmt::Debug + Sized {
    /// Parse a signature from its byte representation
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError>;

    /// Borrow a byte slice representing the serialized form of this signature
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

impl std::fmt::Display for VerificationRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VerificationRelation::AssertionMethod => write!(f, "assertionMethod"),
            VerificationRelation::Authentication => write!(f, "authentication"),
            VerificationRelation::CapabilityInvocation => write!(f, "capabilityInvocation"),
            VerificationRelation::CapabilityDelegation => write!(f, "capabilityDelegation"),
        }
    }
}

impl Signature for Ed25519Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        Ok(Ed25519Signature(bytes.to_vec()))
    }
}
