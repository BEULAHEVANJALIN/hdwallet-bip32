use crate::{
    Bip32Error,
    extended_key::{ExtendedPrivKey, ExtendedPubKey, HARDENED_OFFSET},
};
use secp256k1::Secp256k1;
use std::str::FromStr;

/// Hardened offset constant for BIP-32 derivation.
use std::fmt;

/// A BIP-32 derivation path (e.g., "m/44'/0'/0'/0/1").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath(pub Vec<u32>);

impl FromStr for DerivationPath {
    type Err = Bip32Error;

    /// Parses a path string like "m/44'/0'/0'/0/0" or "44/0/0/0".
    fn from_str(s: &str) -> Result<Self, Bip32Error> {
        let s = s.trim();
        // Strip optional "m/" or leading "m"
        let without_master = if s.eq_ignore_ascii_case("m") {
            return Ok(DerivationPath(Vec::new()));
        } else if let Some(stripped) = s.strip_prefix("m/") {
            stripped
        } else if let Some(stripped) = s.strip_prefix("M/") {
            stripped
        } else {
            s
        };

        if without_master.is_empty() {
            return Ok(DerivationPath(Vec::new()));
        }

        let mut indices = Vec::new();
        for part in without_master.split('/') {
            if part.is_empty() {
                return Err(Bip32Error::InvalidDerivationPath);
            }
            let hardened = part.ends_with('"') || part.ends_with('h') || part.ends_with("'");
            let num_str = if hardened {
                &part[..part.len() - 1]
            } else {
                part
            };
            let idx: u32 = num_str
                .parse()
                .map_err(|_| Bip32Error::InvalidDerivationPath)?;
            let full_idx = if hardened {
                idx.checked_add(HARDENED_OFFSET)
                    .ok_or(Bip32Error::InvalidDerivationPath)?
            } else {
                idx
            };
            indices.push(full_idx);
        }
        Ok(DerivationPath(indices))
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return write!(f, "m");
        }
        let parts: Vec<String> = self
            .0
            .iter()
            .map(|&i| {
                if i >= HARDENED_OFFSET {
                    format!("{}'", i - HARDENED_OFFSET)
                } else {
                    i.to_string()
                }
            })
            .collect();
        write!(f, "m/{}", parts.join("/"))
    }
}

impl DerivationPath {
    /// Derive a private extended key along this path from a master xprv.
    pub fn derive_private(&self, master: &ExtendedPrivKey) -> Result<ExtendedPrivKey, Bip32Error> {
        let secp = Secp256k1::new();
        let mut key = master.clone();
        for &index in &self.0 {
            key = key.derive_private_child(&secp, index)?;
        }
        Ok(key)
    }

    /// Derive a public extended key along this path from an xpub (non-hardened only).
    pub fn derive_public(&self, master: &ExtendedPubKey) -> Result<ExtendedPubKey, Bip32Error> {
        let secp = Secp256k1::new();
        let mut key = master.clone();
        for &index in &self.0 {
            if index >= HARDENED_OFFSET {
                return Err(Bip32Error::InvalidDerivationPath);
            }
            key = key.derive_public_child(&secp, index)?;
        }
        Ok(key)
    }
}
