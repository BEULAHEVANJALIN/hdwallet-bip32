use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC key length should be > 0");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    result.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn hmac_sha512_empty_data() {
        let key = b"key";
        let expected = hex!(
            "84fa5aa0279bbc473267d05a53ea03310a987cecc4c1535ff29b6d76b8f1444a728df3aadb89d4a9a6709e1998f373566e8f824a8ca93b1821f0b69bc2a2f65e"
        );
        assert_eq!(hmac_sha512(key, b""), expected);
    }

    /// Test case from RFC 4231
    #[test]
    fn hmac_sha512_rfc1() {
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let expected = hex!(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
        assert_eq!(hmac_sha512(&key, data), expected);
    }

    /// Test case from RFC 4231
    #[test]
    fn hmac_sha512_rfc2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex!(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
        assert_eq!(hmac_sha512(key, data), expected);
    }
}
