use crate::curve::Curve;
use crate::traits::{ChainSigner, SignOutput, SignerError};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ows_core::ChainType;
use sha2::{Digest, Sha256};
use stellar_xdr::curr::{
    Hash, HashIdPreimageSorobanAuthorization, Limits, MuxedAccount, Preconditions, ReadXdr,
    Transaction, TransactionEnvelope, TransactionExt, TransactionSignaturePayload,
    TransactionSignaturePayloadTaggedTransaction, WriteXdr,
};

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
    pub const PUBNET_NETWORK_PASSPHRASE: &'static str =
        "Public Global Stellar Network ; September 2015";
    pub const TESTNET_NETWORK_PASSPHRASE: &'static str = "Test SDF Network ; September 2015";

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

    fn network_passphrase(chain_id: &str) -> Result<&'static str, SignerError> {
        match chain_id {
            "stellar:pubnet" => Ok(Self::PUBNET_NETWORK_PASSPHRASE),
            "stellar:testnet" => Ok(Self::TESTNET_NETWORK_PASSPHRASE),
            _ => Err(SignerError::InvalidTransaction(format!(
                "unsupported Stellar chain for transaction signing: {chain_id} (expected stellar:pubnet or stellar:testnet)"
            ))),
        }
    }

    fn network_id(passphrase: &str) -> Hash {
        let digest: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
        Hash(digest)
    }

    fn network_id_for_chain(chain_id: &str) -> Result<Hash, SignerError> {
        Ok(Self::network_id(Self::network_passphrase(chain_id)?))
    }

    fn transaction_from_v0(tx: &stellar_xdr::curr::TransactionV0) -> Transaction {
        Transaction {
            source_account: MuxedAccount::Ed25519(tx.source_account_ed25519.clone()),
            fee: tx.fee,
            seq_num: tx.seq_num.clone(),
            cond: tx
                .time_bounds
                .clone()
                .map_or(Preconditions::None, Preconditions::Time),
            memo: tx.memo.clone(),
            operations: tx.operations.clone(),
            ext: TransactionExt::V0,
        }
    }

    pub fn transaction_signature_payload_xdr(
        &self,
        chain_id: &str,
        envelope_xdr: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let envelope =
            TransactionEnvelope::from_xdr(envelope_xdr, Limits::none()).map_err(|e| {
                SignerError::InvalidTransaction(format!(
                    "invalid Stellar transaction envelope XDR: {e}"
                ))
            })?;
        let network_passphrase = Self::network_passphrase(chain_id)?;

        let tagged_transaction = match envelope {
            TransactionEnvelope::TxV0(envelope) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(Self::transaction_from_v0(
                    &envelope.tx,
                ))
            }
            TransactionEnvelope::Tx(envelope) => {
                TransactionSignaturePayloadTaggedTransaction::Tx(envelope.tx)
            }
            TransactionEnvelope::TxFeeBump(envelope) => {
                TransactionSignaturePayloadTaggedTransaction::TxFeeBump(envelope.tx)
            }
        };

        TransactionSignaturePayload {
            network_id: Self::network_id(network_passphrase),
            tagged_transaction,
        }
        .to_xdr(Limits::none())
        .map_err(|e| {
            SignerError::InvalidTransaction(format!(
                "failed to encode Stellar transaction signature payload: {e}"
            ))
        })
    }

    pub fn sign_auth_entry(
        &self,
        private_key: &[u8],
        chain_id: &str,
        preimage_xdr: &[u8],
    ) -> Result<StellarAuthEntrySignature, SignerError> {
        let preimage = HashIdPreimageSorobanAuthorization::from_xdr(preimage_xdr, Limits::none())
            .map_err(|e| {
            SignerError::InvalidMessage(format!("invalid Stellar auth-entry preimage XDR: {e}"))
        })?;
        let expected_network_id = Self::network_id_for_chain(chain_id).map_err(|e| {
            SignerError::InvalidMessage(format!(
                "unsupported Stellar chain for auth-entry signing: {e}"
            ))
        })?;
        if preimage.network_id.as_slice() != expected_network_id.as_slice() {
            return Err(SignerError::InvalidMessage(format!(
                "auth-entry preimage network_id does not match requested Stellar chain: {chain_id}"
            )));
        }

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
        private_key: &[u8],
        tx_bytes: &[u8],
    ) -> Result<SignOutput, SignerError> {
        TransactionSignaturePayload::from_xdr(tx_bytes, Limits::none()).map_err(|e| {
            SignerError::InvalidTransaction(format!(
                "invalid Stellar transaction signature payload XDR: {e}"
            ))
        })?;

        let signing_key = Self::signing_key(private_key)?;
        let payload_hash = Sha256::digest(tx_bytes);
        let signature = signing_key.sign(&payload_hash);
        Ok(SignOutput {
            signature: signature.to_bytes().to_vec(),
            recovery_id: None,
            public_key: Some(signing_key.verifying_key().as_bytes().to_vec()),
        })
    }

    fn default_derivation_path(&self, index: u32) -> String {
        // Ed25519 derivation in this codebase requires hardened-only paths.
        format!("m/44'/148'/{}'", index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::Verifier;
    use serde::Deserialize;
    use std::fs;
    use std::path::PathBuf;
    use stellar_xdr::curr::{
        FeeBumpTransaction, FeeBumpTransactionEnvelope, FeeBumpTransactionExt,
        FeeBumpTransactionInnerTx, HashIdPreimageSorobanAuthorization, Limits, Memo, Operation,
        OperationBody, PaymentOp, Preconditions, PublicKey, ScAddress, ScVal, SequenceNumber,
        SorobanAuthorizedFunction, TimeBounds, Transaction, TransactionEnvelope, TransactionExt,
        TransactionSignaturePayload, TransactionV0, TransactionV0Envelope, TransactionV0Ext,
        TransactionV1Envelope, Uint256,
    };

    #[derive(Debug, Deserialize)]
    struct AuthEntryFixture {
        network_passphrase: String,
        network_id_hex: String,
        nonce: i64,
        signature_expiration_ledger: u32,
        invocation_contract_address_kind: String,
        invocation_contract_hash_hex: String,
        invocation_function_name: String,
        invocation_arg_summary: Vec<String>,
        preimage_xdr_base64: String,
        preimage_xdr_hex: String,
        payload_hash_hex: String,
        private_key_hex: String,
        public_key_hex: String,
        signer_g_address: String,
        signature_hex: String,
    }

    fn load_auth_entry_fixture() -> AuthEntryFixture {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../testdata/stellar/auth_entry_external_ed25519.json");
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

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
        let fixture = load_auth_entry_fixture();
        let privkey = hex::decode(&fixture.private_key_hex).unwrap();
        let signer = StellarSigner;
        let preimage = base64::engine::general_purpose::STANDARD
            .decode(&fixture.preimage_xdr_base64)
            .unwrap();

        let signed = signer
            .sign_auth_entry(&privkey, "stellar:testnet", &preimage)
            .unwrap();
        assert_eq!(signed.signature.len(), 64);
        assert_eq!(signed.public_key.len(), 32);
        assert_eq!(hex::encode(&signed.payload_hash), fixture.payload_hash_hex);
        assert_eq!(hex::encode(&signed.public_key), fixture.public_key_hex);
        assert_eq!(signed.address, fixture.signer_g_address);
        assert_eq!(hex::encode(&signed.signature), fixture.signature_hex);

        let signing_key = SigningKey::from_bytes(&privkey.clone().try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig =
            ed25519_dalek::Signature::from_bytes(&signed.signature.clone().try_into().unwrap());
        verifying_key.verify(&signed.payload_hash, &sig).unwrap();
    }

    fn sample_v1_transaction_envelope() -> Vec<u8> {
        let tx = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: Transaction {
                source_account: stellar_xdr::curr::MuxedAccount::Ed25519(
                    stellar_xdr::curr::Uint256([0x11; 32]),
                ),
                fee: 100,
                seq_num: SequenceNumber(7),
                cond: Preconditions::Time(TimeBounds {
                    min_time: stellar_xdr::curr::TimePoint(0),
                    max_time: stellar_xdr::curr::TimePoint(123456),
                }),
                memo: Memo::Text("ows".as_bytes().try_into().unwrap()),
                operations: vec![Operation {
                    source_account: None,
                    body: OperationBody::Payment(PaymentOp {
                        destination: stellar_xdr::curr::MuxedAccount::Ed25519(
                            stellar_xdr::curr::Uint256([0x22; 32]),
                        ),
                        asset: stellar_xdr::curr::Asset::Native,
                        amount: 1000,
                    }),
                }]
                .try_into()
                .unwrap(),
                ext: TransactionExt::V0,
            },
            signatures: vec![].try_into().unwrap(),
        });
        tx.to_xdr(Limits::none()).unwrap()
    }

    fn sample_v0_transaction_envelope() -> Vec<u8> {
        let tx = TransactionEnvelope::TxV0(TransactionV0Envelope {
            tx: TransactionV0 {
                source_account_ed25519: Uint256([0x33; 32]),
                fee: 100,
                seq_num: SequenceNumber(8),
                time_bounds: Some(TimeBounds {
                    min_time: stellar_xdr::curr::TimePoint(0),
                    max_time: stellar_xdr::curr::TimePoint(123999),
                }),
                memo: Memo::Text("owsv0".as_bytes().try_into().unwrap()),
                operations: vec![Operation {
                    source_account: None,
                    body: OperationBody::Payment(PaymentOp {
                        destination: stellar_xdr::curr::MuxedAccount::Ed25519(
                            stellar_xdr::curr::Uint256([0x44; 32]),
                        ),
                        asset: stellar_xdr::curr::Asset::Native,
                        amount: 555,
                    }),
                }]
                .try_into()
                .unwrap(),
                ext: TransactionV0Ext::V0,
            },
            signatures: vec![].try_into().unwrap(),
        });
        tx.to_xdr(Limits::none()).unwrap()
    }

    fn sample_fee_bump_transaction_envelope() -> Vec<u8> {
        let inner = TransactionV1Envelope {
            tx: Transaction {
                source_account: stellar_xdr::curr::MuxedAccount::Ed25519(
                    stellar_xdr::curr::Uint256([0x55; 32]),
                ),
                fee: 100,
                seq_num: SequenceNumber(9),
                cond: Preconditions::None,
                memo: Memo::Text("owsfb".as_bytes().try_into().unwrap()),
                operations: vec![Operation {
                    source_account: None,
                    body: OperationBody::Payment(PaymentOp {
                        destination: stellar_xdr::curr::MuxedAccount::Ed25519(
                            stellar_xdr::curr::Uint256([0x66; 32]),
                        ),
                        asset: stellar_xdr::curr::Asset::Native,
                        amount: 777,
                    }),
                }]
                .try_into()
                .unwrap(),
                ext: TransactionExt::V0,
            },
            signatures: vec![].try_into().unwrap(),
        };

        let envelope = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
            tx: FeeBumpTransaction {
                fee_source: stellar_xdr::curr::MuxedAccount::Ed25519(stellar_xdr::curr::Uint256(
                    [0x77; 32],
                )),
                fee: 1000,
                inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
                ext: FeeBumpTransactionExt::V0,
            },
            signatures: vec![].try_into().unwrap(),
        });
        envelope.to_xdr(Limits::none()).unwrap()
    }

    #[test]
    fn test_signature_payload_xdr_from_v1_envelope() {
        let signer = StellarSigner;
        let envelope_xdr = sample_v1_transaction_envelope();
        let payload_xdr = signer
            .transaction_signature_payload_xdr("stellar:testnet", &envelope_xdr)
            .unwrap();

        let payload = TransactionSignaturePayload::from_xdr(&payload_xdr, Limits::none()).unwrap();
        assert_eq!(
            hex::encode(payload.network_id.as_slice()),
            hex::encode(Sha256::digest(
                StellarSigner::TESTNET_NETWORK_PASSPHRASE.as_bytes()
            ))
        );
        assert!(matches!(
            payload.tagged_transaction,
            stellar_xdr::curr::TransactionSignaturePayloadTaggedTransaction::Tx(_)
        ));
    }

    #[test]
    fn test_signature_payload_xdr_from_v0_envelope() {
        let signer = StellarSigner;
        let envelope_xdr = sample_v0_transaction_envelope();
        let payload_xdr = signer
            .transaction_signature_payload_xdr("stellar:testnet", &envelope_xdr)
            .unwrap();

        let payload = TransactionSignaturePayload::from_xdr(&payload_xdr, Limits::none()).unwrap();
        assert!(matches!(
            payload.tagged_transaction,
            stellar_xdr::curr::TransactionSignaturePayloadTaggedTransaction::Tx(_)
        ));
    }

    #[test]
    fn test_signature_payload_xdr_from_fee_bump_envelope() {
        let signer = StellarSigner;
        let envelope_xdr = sample_fee_bump_transaction_envelope();
        let payload_xdr = signer
            .transaction_signature_payload_xdr("stellar:testnet", &envelope_xdr)
            .unwrap();

        let payload = TransactionSignaturePayload::from_xdr(&payload_xdr, Limits::none()).unwrap();
        assert!(matches!(
            payload.tagged_transaction,
            stellar_xdr::curr::TransactionSignaturePayloadTaggedTransaction::TxFeeBump(_)
        ));
    }

    #[test]
    fn test_sign_transaction_hashes_signature_payload() {
        let signer = StellarSigner;
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let payload_xdr = signer
            .transaction_signature_payload_xdr("stellar:testnet", &sample_v1_transaction_envelope())
            .unwrap();

        let result = signer.sign_transaction(&privkey, &payload_xdr).unwrap();
        assert_eq!(result.signature.len(), 64);
        assert!(result.recovery_id.is_none());
        assert_eq!(
            hex::encode(result.public_key.clone().unwrap()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );

        let signing_key = SigningKey::from_bytes(&privkey.try_into().unwrap());
        let verifying_key = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&result.signature.try_into().unwrap());
        verifying_key
            .verify(&Sha256::digest(&payload_xdr), &sig)
            .unwrap();
    }

    #[test]
    fn test_auth_entry_fixture_base64_and_hex_match() {
        let fixture = load_auth_entry_fixture();
        let decoded_base64 = base64::engine::general_purpose::STANDARD
            .decode(&fixture.preimage_xdr_base64)
            .unwrap();
        let decoded_hex = hex::decode(&fixture.preimage_xdr_hex).unwrap();
        assert_eq!(decoded_base64, decoded_hex);
        assert_eq!(
            hex::encode(Sha256::digest(&decoded_base64)),
            fixture.payload_hash_hex
        );
    }

    #[test]
    fn test_auth_entry_fixture_is_real_soroban_authorization_xdr() {
        let fixture = load_auth_entry_fixture();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&fixture.preimage_xdr_base64)
            .unwrap();
        let preimage =
            HashIdPreimageSorobanAuthorization::from_xdr(&decoded, Limits::none()).unwrap();

        assert_eq!(
            fixture.network_passphrase,
            "Test SDF Network ; September 2015"
        );
        assert_eq!(
            hex::encode(preimage.network_id.as_slice()),
            fixture.network_id_hex
        );
        assert_eq!(preimage.nonce, fixture.nonce);
        assert_eq!(
            preimage.signature_expiration_ledger,
            fixture.signature_expiration_ledger
        );
        assert_eq!(fixture.invocation_contract_address_kind, "contract");
        assert_eq!(
            fixture.invocation_arg_summary,
            ["address:<signer_g_address>", "u32:100"]
        );

        match preimage.invocation.function {
            SorobanAuthorizedFunction::ContractFn(args) => {
                match args.contract_address {
                    ScAddress::Contract(hash) => {
                        assert_eq!(
                            hex::encode(hash.as_slice()),
                            fixture.invocation_contract_hash_hex
                        );
                    }
                    other => panic!("expected contract address, got {other:?}"),
                }

                assert_eq!(
                    args.function_name.0.to_utf8_string().unwrap(),
                    fixture.invocation_function_name
                );
                assert_eq!(args.args.len(), 2);
                match &args.args[0] {
                    ScVal::Address(ScAddress::Account(account_id)) => match account_id.as_ref() {
                        PublicKey::PublicKeyTypeEd25519(pk) => {
                            assert_eq!(hex::encode(pk.as_slice()), fixture.public_key_hex);
                        }
                    },
                    other => panic!("expected first arg to be signer address, got {other:?}"),
                }
                assert!(matches!(&args.args[1], ScVal::U32(100)));
                assert!(preimage.invocation.sub_invocations.is_empty());
            }
            other => panic!("expected contract invocation, got {other:?}"),
        }
    }

    #[test]
    fn test_transaction_signature_payload_rejects_invalid_xdr() {
        let signer = StellarSigner;
        let err = signer
            .sign_transaction(
                &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                    .unwrap(),
                b"not-valid-xdr",
            )
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("invalid Stellar transaction signature payload XDR"));
    }

    #[test]
    fn test_sign_auth_entry_rejects_invalid_xdr() {
        let signer = StellarSigner;
        let privkey =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();

        let err = signer
            .sign_auth_entry(&privkey, "stellar:testnet", b"not-valid-xdr")
            .unwrap_err();
        assert!(matches!(err, SignerError::InvalidMessage(_)));
        assert!(err
            .to_string()
            .contains("invalid Stellar auth-entry preimage XDR"));
    }

    #[test]
    fn test_sign_auth_entry_rejects_network_mismatch() {
        let fixture = load_auth_entry_fixture();
        let privkey = hex::decode(&fixture.private_key_hex).unwrap();
        let preimage = base64::engine::general_purpose::STANDARD
            .decode(&fixture.preimage_xdr_base64)
            .unwrap();

        let err = StellarSigner
            .sign_auth_entry(&privkey, "stellar:pubnet", &preimage)
            .unwrap_err();
        assert!(matches!(err, SignerError::InvalidMessage(_)));
        assert!(err
            .to_string()
            .contains("network_id does not match requested Stellar chain"));
    }

    #[test]
    fn test_derivation_path() {
        let signer = StellarSigner;
        assert_eq!(signer.default_derivation_path(0), "m/44'/148'/0'");
        assert_eq!(signer.default_derivation_path(7), "m/44'/148'/7'");
    }
}
