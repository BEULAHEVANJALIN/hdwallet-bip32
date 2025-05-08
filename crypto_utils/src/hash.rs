use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    result.into()
}

pub fn sha256d(input: &[u8]) -> [u8; 32] {
    let first = sha256(input);
    sha256(&first)
}

pub fn sha512(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(input);
    let result = hasher.finalize();
    result.into()
}

pub fn ripemd160(input: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn sha256_empty() {
        let expected = hex!(
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha256(b""), expected);
    }

    #[test]
    fn sha256_abc() {
        let expected = hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256(b"abc"), expected);
    }

    #[test]
    fn sha256_long_ascii() {
        let expected = hex!("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
        assert_eq!(
            sha256(b"The quick brown fox jumps over the lazy dog"),
            expected
        );
    }

    #[test]
    fn sha256d_empty() {
        let expected = hex!("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
        assert_eq!(sha256d(b""), expected);
    }

    #[test]
    fn sha256d_hello() {
        let expected = hex!("9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50");
        assert_eq!(sha256d(b"hello"), expected);
    }

    #[test]
    fn sha256d_quick_brown() {
        let expected = hex!("6d37795021e544d82b41850edf7aabab9a0ebe274e54a519840c4666f35b3937");
        assert_eq!(
            sha256d(b"The quick brown fox jumps over the lazy dog"),
            expected
        );
    }

    #[test]
    fn sha256d_long_input() {
        let data = vec![0u8; 1000];
        let expected = hex!("3fa2b684fa9d80f04b70187e6c9ff1c8dd422ce1846beb79cf5e1546c7062d41");
        assert_eq!(sha256d(&data), expected);
    }

    #[test]
    fn sha512_empty() {
        let expected = hex!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(sha512(b""), expected);
    }

    #[test]
    fn sha512_abc() {
        let expected = hex!(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(sha512(b"abc"), expected);
    }

    #[test]
    fn sha512_long_ascii() {
        let expected = hex!(
            "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"
        );
        assert_eq!(
            sha512(b"The quick brown fox jumps over the lazy dog"),
            expected
        );
    }

    #[test]
    fn ripemd160_empty() {
        let expected = hex!("9c1185a5c5e9fc54612808977ee8f548b2258d31");
        assert_eq!(ripemd160(b""), expected);
    }

    #[test]
    fn ripemd160_abc() {
        let expected = hex!("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        assert_eq!(ripemd160(b"abc"), expected);
    }

    #[test]
    fn ripemd160_message_digest() {
        let expected = hex!("5d0689ef49d2fae572b881b123a85ffa21595f36");
        assert_eq!(ripemd160(b"message digest"), expected);
    }

    #[test]
    fn ripemd160_quick_brown() {
        let expected = hex!("37f332f68db77bd9d7edd4969571ad671cf9dd3b");
        assert_eq!(
            ripemd160(b"The quick brown fox jumps over the lazy dog"),
            expected
        );
    }
}
