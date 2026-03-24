use serde::{Deserialize, Serialize};

/// A single account within a wallet (one per chain family).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    pub chain_id: String,
    pub address: String,
    pub derivation_path: String,
}

/// Binding-friendly wallet information (no crypto envelope exposed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub id: String,
    pub name: String,
    pub accounts: Vec<AccountInfo>,
    pub created_at: String,
}

/// Result from a signing operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResult {
    pub signature: String,
    pub recovery_id: Option<u8>,
}

/// Result from signing a serialized Stellar auth-entry preimage XDR payload.
/// The returned address is the Stellar G-address for the signer key, not the
/// deployed smart-account C-address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StellarAuthEntryResult {
    pub address: String,
    pub public_key: String,
    pub payload_hash: String,
    pub signature: String,
}

/// Result from a sign-and-send operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendResult {
    pub tx_hash: String,
}
