#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip32Error {
    InvalidMasterKey,
    InvalidChildKey,
    InvalidKeyData,
    InvalidBase58,
    InvalidChecksum,
    InvalidLength,
    InvalidVersion,
    InvalidDerivationPath,
}
