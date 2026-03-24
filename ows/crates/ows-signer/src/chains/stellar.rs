use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;
use sha2::{Digest, Sha256};

/// Output from signing a serialized Stellar auth-entry preimage XDR payload.
#[derive(Debug, Clone)]
pub struct StellarAuthEntrySignature {
    pub address: String,
    pub public_key: Vec<u8>,
    pub payload_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Stellar chain signer backed by Ed25519.
pub struct StellarSigner;

impl StellarSigner {
    fn signing_key(private_key: &[u8]) -> Result<SigningKey, SignerError> {
        let key_bytes: [u8; 32] = private_key.try_into().map_err(|_| {
            SignerError::InvalidPrivateKey(format!("expected 32 bytes, got {}", private_key.len()))
        })?;
        Ok(SigningKey::from_bytes(&key_bytes))
    }

    fn encode_address(verifying_key: &VerifyingKey) -> Result<String, SignerError> {
        stellar_strkey::ed25519::PublicKey::from_payload(verifying_key.as_bytes())
            .map(|pk| pk.to_string())
            .map_err(|e| SignerError::AddressDerivationFailed(e.to_string()))
    }

    pub fn sign_auth_entry(
        &self,
        private_key: &[u8],
        preimage_xdr: &[u8],
    ) -> Result<StellarAuthEntrySignature, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let verifying_key = signing_key.verifying_key();
        let payload_hash = Sha256::digest(preimage_xdr);
        let signature = signing_key.sign(&payload_hash);

        Ok(StellarAuthEntrySignature {
            address: Self::encode_address(&verifying_key)?,
            public_key: verifying_key.as_bytes().to_vec(),
            payload_hash: payload_hash.to_vec(),
            signature: signature.to_bytes().to_vec(),
        })
    }
}

impl ChainSigner for StellarSigner {
    fn chain_type(&self) -> ChainType {
        ChainType::Stellar
    }

    fn curve(&self) -> Curve {
        Curve::Ed25519
    }

    fn coin_type(&self) -> u32 {
        148
    }

    fn derive_address(&self, private_key: &[u8]) -> Result<String, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        Self::encode_address(&signing_key.verifying_key())
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        let signing_key = Self::signing_key(private_key)?;
        let signature = signing_key.sign(message);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(signing_key.verifying_key().as_bytes().to_vec()),
        })
    }

    fn sign_message(&self, private_key: &[u8], message: &[u8]) -> Result<SignOutput, SignerError> {
        self.sign(private_key, message)
    }

    fn sign_transaction(
        &self,
        _private_key: &[u8],
        _tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        Err(SignerError::InvalidTransaction(
            "generic transaction signing is not supported for Stellar; use sign_auth_entry for Soroban smart-account auth flows".into(),
        ))
    }

    fn default_derivation_path(&self, index: u32) -> String {
        // Ed25519 derivation in this codebase requires hardened-only paths.
        format!("m/44'/148'/{}'", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[test]
    fn test_address_encoding() {
        let signer = StellarSigner;
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let address = signer.derive_address(&privkey).unwrap();
        assert!(address.starts_with('G'));
        assert_eq!(address.len(), 56);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = StellarSigner;
        let message = b"stellar-test-message";

        let result = signer.sign(&privkey, message).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key.verify(message, &sig).unwrap();
    }

    #[test]
    fn test_sign_auth_entry_hashes_preimage() {
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = StellarSigner;
        let preimage = b"fake-auth-preimage-xdr";

        let signed = signer.sign_auth_entry(&privkey, preimage).unwrap();
        assert_eq!(signed.signature.len(), 64);
        assert_eq!(signed.public_key.len(), 32);
        assert_eq!(signed.payload_hash, Sha256::digest(preimage).to_vec());
        assert!(signed.address.starts_with('G'));
    }

    #[test]
    fn test_derivation_path() {
        let signer = StellarSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/148'/0'");
        assert_eq!(signer.default_derivation_path(7), "m/44'/148'/7'");
    }
}
