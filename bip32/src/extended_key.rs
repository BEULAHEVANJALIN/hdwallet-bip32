use crate::error::Bip32Error;
use crypto_utils::{
    base58::{self, Base58Error, base58_check_decode},
    hash::{ripemd160, sha256},
    hmac::hmac_sha512,
};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

/// Index offset for hardened children (index >= 0x80000000) i.e., 0x80000000 = 2³¹
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

// Version bytes for serialization
const VERSION_MAINNET_PRIVATE: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
const VERSION_MAINNET_PUBLIC: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
const VERSION_TESTNET_PRIVATE: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
const VERSION_TESTNET_PUBLIC: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];

// Normal child indices: 0 to 2³¹-1
// Hardened child indices: 2³¹ (0x8000_0000) to 2³²-1

/// Extended private key (xprv)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedPrivKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_index: u32,
    pub chain_code: [u8; 32],
    pub private_key: SecretKey,
}

/// Extended public key (xpub)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedPubKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_index: u32,
    pub chain_code: [u8; 32],
    pub public_key: PublicKey,
}

/// 4-byte parent fingerprint: HASH160(SHA256(pubkey))[0..4]
fn fingerprint(pubkey: &PublicKey) -> [u8; 4] {
    let serialized = pubkey.serialize();
    let hash160 = ripemd160(&sha256(&serialized));
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&hash160[..4]);
    fp
}

impl ExtendedPrivKey {
    /// Master extended private key from a seed
    pub fn new_master(seed: &[u8]) -> Result<Self, Bip32Error> {
        let len = seed.len();
        if len < 16 || len > 64 {
            return Err(Bip32Error::InvalidLength);
        }
        let i = hmac_sha512(b"Bitcoin seed", seed);
        let (il, ir) = i.split_at(32);
        let private_key = SecretKey::from_slice(il).map_err(|_| Bip32Error::InvalidMasterKey)?;
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(ir);
        Ok(ExtendedPrivKey {
            depth: 0,
            parent_fingerprint: [0u8; 4],
            child_index: 0,
            chain_code,
            private_key,
        })
    }

    /// Convert an ExtendedPubKey (xprv) into its corresponding ExtendedPubKey (xpub)
    pub fn to_extended_pub(&self, secp: &Secp256k1<secp256k1::All>) -> ExtendedPubKey {
        let public_key = PublicKey::from_secret_key(secp, &self.private_key);
        ExtendedPubKey {
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_index: self.child_index,
            chain_code: self.chain_code,
            public_key,
        }
    }

    /// Child key derivation for Private Keys (CKDpriv)
    pub fn derive_private_child(
        &self,
        secp: &Secp256k1<secp256k1::All>,
        index: u32,
    ) -> Result<Self, Bip32Error> {
        // data for HMAC
        // Hardened: 1-byte 0x00 + 32-byte privkey + 4-byte index
        let mut data = Vec::with_capacity(1 + 33 + 4);
        if index >= HARDENED_OFFSET {
            data.push(0u8);
            data.extend(&self.private_key[..]);
        } else {
            let parent_pub = PublicKey::from_secret_key(secp, &self.private_key);
            data.extend(&parent_pub.serialize());
        }
        data.extend(&index.to_be_bytes());

        // HMAC-SHA512
        let i = hmac_sha512(&self.chain_code, &data);
        let (il, ir) = i.split_at(32);

        // Tweak private key, child private key = (parent private key + tweak IL) modulo n
        let il_arr: [u8; 32] = il.try_into().expect("HMAC output must be 32 bytes");
        let tweak = Scalar::from_be_bytes(il_arr).map_err(|_| Bip32Error::InvalidChildKey)?;
        let child_sk = self
            .private_key
            .clone()
            .add_tweak(&tweak)
            .map_err(|_| Bip32Error::InvalidChildKey)?;

        // Child chain code = IR
        let mut child_cc = [0u8; 32];
        child_cc.copy_from_slice(ir);

        // Metadata: depth, parent fingerprint, index
        let parent_pub = PublicKey::from_secret_key(secp, &self.private_key);
        let parent_fp = fingerprint(&parent_pub);
        let child_depth = self
            .depth
            .checked_add(1)
            .ok_or(Bip32Error::InvalidChildKey)?;

        Ok(ExtendedPrivKey {
            depth: child_depth,
            parent_fingerprint: parent_fp,
            child_index: index,
            chain_code: child_cc,
            private_key: child_sk,
        })
    }

    /// Serialize this xprv into a Base58Check string
    pub fn to_base58(&self, network: Network) -> String {
        // version
        let version = match network {
            Network::Mainnet => VERSION_MAINNET_PRIVATE,
            Network::Testnet => VERSION_TESTNET_PRIVATE,
        };
        // payload: depth (1) | parent_fp (4) | child_index (4) | chain_code (32) | key_data (33)
        let mut payload = Vec::with_capacity(78);
        payload.extend(&version);
        payload.push(self.depth);
        payload.extend(&self.parent_fingerprint);
        payload.extend(&self.child_index.to_be_bytes());
        payload.extend(&self.chain_code);
        payload.push(0u8); // leading zero
        payload.extend(&self.private_key[..]);

        // Base58Check encode
        base58::base58_check_encode(&payload)
    }

    /// Deserialize an xprv from a Base58Check string
    pub fn from_base58(s: &str) -> Result<Self, Bip32Error> {
        // Decode Base58Check (payload + 4-byte checksum)
        let data = base58_check_decode(s).map_err(|e| match e {
            Base58Error::InvalidChecksum => Bip32Error::InvalidChecksum,
            Base58Error::InvalidLength => Bip32Error::InvalidLength,
            Base58Error::InvalidCharacter(_) => Bip32Error::InvalidBase58,
        })?;
        // exactly 78 bytes (no checksum)
        if data.len() != 78 {
            return Err(Bip32Error::InvalidLength);
        }
        // Extract and validate version bytes
        let version: [u8; 4] = data[0..4].try_into().unwrap();
        match version {
            VERSION_MAINNET_PRIVATE | VERSION_TESTNET_PRIVATE => {}
            _ => return Err(Bip32Error::InvalidVersion),
        }
        // Parse fields
        let depth = data[4];
        let mut parent_fp = [0u8; 4];
        parent_fp.copy_from_slice(&data[5..9]);
        let child_index = u32::from_be_bytes(data[9..13].try_into().unwrap());
        if depth == 0 && (parent_fp != [0u8; 4] || child_index != 0) {
            return Err(Bip32Error::InvalidChildKey);
        }
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);
        // Key data: first byte must be 0x00, followed by 32-byte private key
        if data[45] != 0 {
            return Err(Bip32Error::InvalidKeyData);
        }
        let private_key =
            SecretKey::from_slice(&data[46..78]).map_err(|_| Bip32Error::InvalidKeyData)?;
        Ok(ExtendedPrivKey {
            depth,
            parent_fingerprint: parent_fp,
            child_index,
            chain_code,
            private_key,
        })
    }
}

impl ExtendedPubKey {
    /// Derive a child public key for non-hardened indices (CKDpub)
    pub fn derive_public_child(
        &self,
        secp: &Secp256k1<secp256k1::All>,
        index: u32,
    ) -> Result<Self, Bip32Error> {
        if index >= HARDENED_OFFSET {
            return Err(Bip32Error::InvalidDerivationPath);
        }

        // data for HMAC
        // Non-hardened: 33-byte compressed pubkey (parent_pub) + 4-byte index
        let mut data = Vec::with_capacity(33 + 4);
        data.extend(&self.public_key.serialize());
        data.extend(&index.to_be_bytes());

        // HMAC-SHA512
        let i = hmac_sha512(&self.chain_code, &data);
        let (il, ir) = i.split_at(32);

        // Tweak public key
        // Child public key: G*IL + parent_pub
        let tweak_pk = PublicKey::from_secret_key(
            secp,
            &SecretKey::from_slice(il).map_err(|_| Bip32Error::InvalidChildKey)?,
        );
        let child_point = self
            .public_key
            .combine(&tweak_pk)
            .map_err(|_| Bip32Error::InvalidChildKey)?;

        // Child chain code = IR
        let mut child_cc = [0u8; 32];
        child_cc.copy_from_slice(ir);

        // Metadata: depth, parent fingerprint, index
        let parent_fp = fingerprint(&self.public_key);
        let child_depth = self
            .depth
            .checked_add(1)
            .ok_or(Bip32Error::InvalidChildKey)?;

        Ok(ExtendedPubKey {
            depth: child_depth,
            parent_fingerprint: parent_fp,
            child_index: index,
            chain_code: child_cc,
            public_key: child_point,
        })
    }

    /// Serialize to Base58Check (xpub)
    pub fn to_base58(&self, network: Network) -> String {
        let version = match network {
            Network::Mainnet => VERSION_MAINNET_PUBLIC,
            Network::Testnet => VERSION_TESTNET_PUBLIC,
        };
        let mut payload = Vec::with_capacity(78);
        payload.extend(&version);
        payload.push(self.depth);
        payload.extend(&self.parent_fingerprint);
        payload.extend(&self.child_index.to_be_bytes());
        payload.extend(&self.chain_code);
        payload.extend(&self.public_key.serialize());
        base58::base58_check_encode(&payload)
    }

    /// Deserialize an xpub from a Base58Check string
    pub fn from_base58(s: &str) -> Result<Self, Bip32Error> {
        // Decode Base58Check
        let data = base58_check_decode(s).map_err(|e| match e {
            Base58Error::InvalidChecksum => Bip32Error::InvalidChecksum,
            Base58Error::InvalidLength => Bip32Error::InvalidLength,
            Base58Error::InvalidCharacter(_) => Bip32Error::InvalidBase58,
        })?;
        // Must be exactly 78 bytes
        if data.len() != 78 {
            return Err(Bip32Error::InvalidLength);
        }
        // Extract and validate version
        let version: [u8; 4] = data[0..4].try_into().unwrap();
        match version {
            VERSION_MAINNET_PUBLIC | VERSION_TESTNET_PUBLIC => {}
            _ => return Err(Bip32Error::InvalidVersion),
        }
        // Parse remaining fields
        let depth = data[4];
        let mut parent_fp = [0u8; 4];
        parent_fp.copy_from_slice(&data[5..9]);
        let child_index = u32::from_be_bytes(data[9..13].try_into().unwrap());
        if depth == 0 && (parent_fp != [0u8; 4] || child_index != 0) {
            return Err(Bip32Error::InvalidChildKey);
        }
        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);
        // Public key data (33 bytes)
        let pk_data = &data[45..78];
        let public_key = PublicKey::from_slice(pk_data).map_err(|_| Bip32Error::InvalidKeyData)?;
        Ok(ExtendedPubKey {
            depth,
            parent_fingerprint: parent_fp,
            child_index,
            chain_code,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::HARDENED_OFFSET;
    use crate::derivation::DerivationPath;
    use crate::{Bip32Error, ExtendedPrivKey, ExtendedPubKey, Network};
    use hex;
    use secp256k1::Secp256k1;

    /// BIP32 Test vector 1
    #[test]
    fn test_vector1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let secp = Secp256k1::new();

        // Chain m
        let m = ExtendedPrivKey::new_master(&seed).unwrap();
        // Expected xprv and xpub from spec
        let expect_xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let expect_xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
        // Check that the master extended private key (xprv) is correct
        assert_eq!(
            m.to_base58(Network::Mainnet),
            expect_xprv,
            "Master extended private key (xprv) does not match expected value"
        );
        let m_pub = m.to_extended_pub(&secp);
        assert_eq!(
            m_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Master extended public key (xpub) does not match expected value"
        );

        // Chain m/0H
        let m0h = m.derive_private_child(&secp, HARDENED_OFFSET).unwrap();
        // Expected xprv and xpub from spec
        let expect_xprv = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
        let expect_xpub = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0h.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0h_pub = m0h.to_extended_pub(&secp);
        assert_eq!(
            m0h_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );

        // Chain m/0H/1
        let m0h1 = m0h.derive_private_child(&secp, 1).unwrap();
        // Expected xprv and xpub from spec (m/0H/1)
        let expect_xprv = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
        let expect_xpub = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0h1.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0h1_pub = m0h1.to_extended_pub(&secp);
        assert_eq!(
            m0h1_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );

        // Chain m/0H/1/2H
        let m0h1_2h = m0h1
            .derive_private_child(&secp, HARDENED_OFFSET + 2)
            .unwrap();
        // Expected xprv and xpub from spec (m/0H/1/2H)
        let expect_xprv = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM";
        let expect_xpub = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0h1_2h.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0h1_2h_pub = m0h1_2h.to_extended_pub(&secp);
        assert_eq!(
            m0h1_2h_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );

        // Chain m/0H/1/2H/2
        let m0h1_2h2 = m0h1_2h.derive_private_child(&secp, 2).unwrap();
        // Expected xprv and xpub from spec (m/0H/1/2H/2)
        let expect_xprv = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334";
        let expect_xpub = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0h1_2h2.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0h1_2h2_pub = m0h1_2h2.to_extended_pub(&secp);
        assert_eq!(
            m0h1_2h2_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );

        // Chain m/0H/1/2H/2/1000000000
        let m0h1_2h2_1000000000 = m0h1_2h2.derive_private_child(&secp, 1000000000).unwrap();
        // Expected xprv and xpub from spec (m/0H/1/2H/2/1000000000)
        let expect_xprv = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76";
        let expect_xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0h1_2h2_1000000000.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0h1_2h2_1000000000_pub = m0h1_2h2_1000000000.to_extended_pub(&secp);
        assert_eq!(
            m0h1_2h2_1000000000_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );
    }

    /// BIP32 Test vector 2
    #[test]
    fn test_vector2() {
        let seed = hex::decode("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
        let secp = Secp256k1::new();

        // Chain m
        let m = ExtendedPrivKey::new_master(&seed).unwrap();
        // Expected xprv and xpub from spec
        let expect_xprv = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
        let expect_xpub = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
        // Check that the master extended private key (xprv) is correct
        assert_eq!(
            m.to_base58(Network::Mainnet),
            expect_xprv,
            "Master extended private key (xprv) does not match expected value"
        );
        let m_pub = m.to_extended_pub(&secp);
        assert_eq!(
            m_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Master extended public key (xpub) does not match expected value"
        );

        // Chain m/0
        let m0 = m.derive_private_child(&secp, 0).unwrap();
        // Expected xprv and xpub from spec (m/0)
        let expect_xprv = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt";
        let expect_xpub = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0_pub = m0.to_extended_pub(&secp);
        assert_eq!(
            m0_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );

        // Chain m/0/2147483647H
        let m0_2147483647h = m0
            .derive_private_child(&secp, HARDENED_OFFSET + 2147483647)
            .unwrap();
        // Expected xprv and xpub from spec (m/0/2147483647H)
        let expect_xprv = "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9";
        let expect_xpub = "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0_2147483647h.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0_2147483647h_pub = m0_2147483647h.to_extended_pub(&secp);
        assert_eq!(
            m0_2147483647h_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );

        // Chain m/0/2147483647H/1
        let m0_2147483647h_1 = m0_2147483647h.derive_private_child(&secp, 1).unwrap();
        // Expected xprv and xpub from spec (m/0/2147483647H/1)
        let expect_xprv = "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef";
        let expect_xpub = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0_2147483647h_1.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0_2147483647h_1_pub = m0_2147483647h_1.to_extended_pub(&secp);
        assert_eq!(
            m0_2147483647h_1_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );

        // Chain m/0/2147483647H/1/2147483646H
        let m0_2147483647h_1_2147483646h = m0_2147483647h_1
            .derive_private_child(&secp, HARDENED_OFFSET + 2147483646)
            .unwrap();
        // Expected xprv and xpub from spec (m/0/2147483647H/1/2147483646H)
        let expect_xprv = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc";
        let expect_xpub = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0_2147483647h_1_2147483646h.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0_2147483647h_1_2147483646h_pub = m0_2147483647h_1_2147483646h.to_extended_pub(&secp);
        assert_eq!(
            m0_2147483647h_1_2147483646h_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );

        // Chain m/0/2147483647H/1/2147483646H/2
        let m0_2147483647h_1_2147483646h_2 = m0_2147483647h_1_2147483646h
            .derive_private_child(&secp, 2)
            .unwrap();
        // Expected xprv and xpub from spec (m/0/2147483647H/1/2147483646H/2)
        let expect_xprv = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";
        let expect_xpub = "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0_2147483647h_1_2147483646h_2.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0_2147483647h_1_2147483646h_2_pub =
            m0_2147483647h_1_2147483646h_2.to_extended_pub(&secp);
        assert_eq!(
            m0_2147483647h_1_2147483646h_2_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );
    }

    /// BIP32 Test vector 3
    #[test]
    fn test_vector3() {
        let seed = hex::decode("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();
        let secp = Secp256k1::new();

        // Chain m
        let m = ExtendedPrivKey::new_master(&seed).unwrap();
        // Expected xprv and xpub from spec (m)
        let expect_xprv = "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6";
        let expect_xpub = "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13";
        // Check that the master extended private key (xprv) is correct
        assert_eq!(
            m.to_base58(Network::Mainnet),
            expect_xprv,
            "Master extended private key (xprv) does not match expected value"
        );
        let m_pub = m.to_extended_pub(&secp);
        assert_eq!(
            m_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Master extended public key (xpub) does not match expected value"
        );

        // Chain m/0H
        let m0h = m.derive_private_child(&secp, HARDENED_OFFSET).unwrap();
        // Expected xprv and xpub from spec (m/0H)
        let expect_xprv = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L";
        let expect_xpub = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0h.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0h_pub = m0h.to_extended_pub(&secp);
        assert_eq!(
            m0h_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );
    }

    /// BIP32 Test vector 4
    #[test]
    fn test_vector4() {
        let seed = hex::decode("3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678")
            .unwrap();
        let secp = Secp256k1::new();

        // Chain m
        let m = ExtendedPrivKey::new_master(&seed).unwrap();
        // Expected xprv and xpub from spec (m)
        let expect_xprv = "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv";
        let expect_xpub = "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa";
        // Check that the master extended private key (xprv) is correct
        assert_eq!(
            m.to_base58(Network::Mainnet),
            expect_xprv,
            "Master extended private key (xprv) does not match expected value"
        );
        let m_pub = m.to_extended_pub(&secp);
        assert_eq!(
            m_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Master extended public key (xpub) does not match expected value"
        );

        // Chain m/0H
        let m0h = m.derive_private_child(&secp, HARDENED_OFFSET).unwrap();
        // Expected xprv and xpub from spec (m/0H)
        let expect_xprv = "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G";
        let expect_xpub = "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0h.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0h_pub = m0h.to_extended_pub(&secp);
        assert_eq!(
            m0h_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );

        // Chain m/0H/1H
        let m0h_1h = m0h
            .derive_private_child(&secp, HARDENED_OFFSET + 1)
            .unwrap();
        // Expected xprv and xpub from spec (m/0H/1H)
        let expect_xprv = "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1";
        let expect_xpub = "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt";
        // Check that the extended private key (xprv) is correct
        assert_eq!(
            m0h_1h.to_base58(Network::Mainnet),
            expect_xprv,
            "Extended private key (xprv) does not match expected value"
        );
        let m0h_1h_pub = m0h_1h.to_extended_pub(&secp);
        assert_eq!(
            m0h_1h_pub.to_base58(Network::Mainnet),
            expect_xpub,
            "Extended public key (xpub) does not match expected value"
        );
    }

    struct Case<'a> {
        key: &'a str,
        expected: Bip32Error,
    }

    /// BIP32 Test vector 5
    #[test]
    fn test_vector5() {
        let cases = [
            // pubkey version / prvkey mismatch
            Case {
                key: "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
                expected: Bip32Error::InvalidKeyData,
            },
            // invalid pubkey prefix 04
            Case {
                key: "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
                expected: Bip32Error::InvalidKeyData,
            },
            // invalid pubkey prefix 01
            Case {
                key: "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
                expected: Bip32Error::InvalidKeyData,
            },
            // zero depth with non-zero parent fingerprint
            Case {
                key: "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
                expected: Bip32Error::InvalidChildKey,
            },
            // zero depth with non-zero index
            Case {
                key: "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
                expected: Bip32Error::InvalidChildKey,
            },
            // invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007
            Case {
                key: "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
                expected: Bip32Error::InvalidKeyData,
            },
        ];

        for case in &cases {
            let err = ExtendedPubKey::from_base58(case.key).unwrap_err();
            assert_eq!(
                err, case.expected,
                "xpub=\"{}\" returned {:?}, expected {:?}",
                case.key, err, case.expected
            );
        }

        let cases = [
            // prvkey version / pubkey mismatch
            Case {
                key: "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
                expected: Bip32Error::InvalidKeyData,
            },
            // invalid prvkey prefix 04
            Case {
                key: "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
                expected: Bip32Error::InvalidKeyData,
            },
            // invalid prvkey prefix 01
            Case {
                key: "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
                expected: Bip32Error::InvalidKeyData,
            },
            // zero depth with non-zero parent fingerprint
            Case {
                key: "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
                expected: Bip32Error::InvalidChildKey,
            },
            // zero depth with non-zero index
            Case {
                key: "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
                expected: Bip32Error::InvalidChildKey,
            },
            // private key 0 not in 1..n-1
            Case {
                key: "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
                expected: Bip32Error::InvalidKeyData,
            },
            // private key n not in 1..n-1
            Case {
                key: "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
                expected: Bip32Error::InvalidKeyData,
            },
            // invalid checksum
            Case {
                key: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
                expected: Bip32Error::InvalidChecksum,
            },
        ];

        for case in &cases {
            let err = ExtendedPrivKey::from_base58(case.key).unwrap_err();
            assert_eq!(
                err, case.expected,
                "xprv=\"{}\" returned {:?}, expected {:?}",
                case.key, err, case.expected
            );
        }

        let unknown = &[
            // unknown extended key version
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
            // unknown extended key version
            "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
        ];

        for &key in unknown {
            assert_eq!(
                ExtendedPubKey::from_base58(key).unwrap_err(),
                Bip32Error::InvalidVersion,
                "xpub \"{}\" should be InvalidVersion",
                key
            );
            assert_eq!(
                ExtendedPrivKey::from_base58(key).unwrap_err(),
                Bip32Error::InvalidVersion,
                "xprv \"{}\" should be InvalidVersion",
                key
            );
        }
    }

    /// Test invalid seed lengths
    #[test]
    fn invalid_seed_length() {
        assert_eq!(
            ExtendedPrivKey::new_master(&[0u8; 15]).unwrap_err(),
            Bip32Error::InvalidLength
        );
        assert_eq!(
            ExtendedPrivKey::new_master(&[0u8; 65]).unwrap_err(),
            Bip32Error::InvalidLength
        );
    }

    /// Test Base58 decode error mapping
    #[test]
    fn base58_errors() {
        // Too short
        assert_eq!(
            ExtendedPrivKey::from_base58("").unwrap_err(),
            Bip32Error::InvalidLength
        );
        // Invalid character
        assert!(matches!(
            ExtendedPrivKey::from_base58("0"),
            Err(Bip32Error::InvalidBase58)
        ));
        // Invalid checksum (alter last character)
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let xprv = ExtendedPrivKey::new_master(&seed)
            .unwrap()
            .to_base58(Network::Mainnet);
        let mut bad = xprv.clone();
        bad.pop();
        bad.push('1');
        assert_eq!(
            ExtendedPrivKey::from_base58(&bad).unwrap_err(),
            Bip32Error::InvalidChecksum
        );
    }

    /// Test hardened-derivation error on public key
    #[test]
    fn hardened_on_xpub() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let secp = Secp256k1::new();
        let xpub = ExtendedPrivKey::new_master(&seed)
            .unwrap()
            .to_extended_pub(&secp);
        assert_eq!(
            xpub.derive_public_child(&secp, HARDENED_OFFSET)
                .unwrap_err(),
            Bip32Error::InvalidDerivationPath
        );
    }

    /// Test DerivationPath parsing and display
    #[test]
    fn test_derivation_path_parse_display() {
        let dp: DerivationPath = "m/0'/1/2'/2/1000000000".parse().unwrap();
        let seq = vec![HARDENED_OFFSET, 1, HARDENED_OFFSET + 2, 2, 1000000000];
        assert_eq!(dp.0, seq);
        assert_eq!(dp.to_string(), "m/0'/1/2'/2/1000000000");
        // Invalid formats
        assert!("m//1".parse::<DerivationPath>().is_err());
        assert!("m/abc".parse::<DerivationPath>().is_err());
    }
}
