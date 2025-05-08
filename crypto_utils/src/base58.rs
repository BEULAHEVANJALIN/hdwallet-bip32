use crate::hash::sha256d;

#[derive(Debug, Clone, PartialEq)]
pub enum Base58Error {
    InvalidCharacter(char),
    InvalidLength,
    InvalidChecksum,
}

pub const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base58_encode(data: &[u8]) -> String {
    let mut input = data.to_vec();
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut encoded: Vec<u8> = Vec::new();
    while !input.is_empty() {
        let mut remainder: u32 = 0;
        let mut new_input: Vec<u8> = Vec::with_capacity(input.len());
        for &byte in input.iter() {
            let acc = (remainder << 8) | byte as u32;
            let digit = (acc / 58) as u8;
            remainder = acc % 58;
            if !new_input.is_empty() || digit != 0 {
                new_input.push(digit);
            }
        }
        if remainder >= 58 {
            panic!("Invalid remainder in Base58 encoding: {}", remainder);
        }
        if !new_input.is_empty() || remainder != 0 {
            encoded.push(BASE58_ALPHABET[remainder as usize]);
        }
        input = new_input;
    }
    encoded.reverse();
    for _ in 0..zeros {
        encoded.insert(0, 49); // ASCII code for '1' i.e., BASE58_ALPHABET[0]
    }
    match String::from_utf8(encoded) {
        Ok(s) => s,
        Err(_) => panic!("Invalid UTF-8 in Base58 encoding"),
    }
}

pub fn base58_decode(s: &str) -> Result<Vec<u8>, Base58Error> {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return Err(Base58Error::InvalidLength);
    }
    let zeros = bytes
        .iter()
        .take_while(|&&b| b == 49) // ASCII code for '1'
        .count();
    let mut input: Vec<u8> = Vec::with_capacity(bytes.len() - zeros);
    for &b in bytes.iter().skip(zeros) {
        match BASE58_ALPHABET.iter().position(|&c| c == b) {
            Some(idx) => input.push(idx as u8),
            None => return Err(Base58Error::InvalidCharacter(b as char)),
        }
    }

    let mut decoded: Vec<u8> = Vec::new();
    while !input.is_empty() {
        let mut remainder: u32 = 0;
        let mut new_input: Vec<u8> = Vec::with_capacity(input.len());
        for &digit in input.iter() {
            let accumulator = remainder * 58 + digit as u32;
            let quotient = (accumulator / 256) as u8;
            remainder = accumulator % 256;
            if !new_input.is_empty() || quotient != 0 {
                new_input.push(quotient);
            }
        }
        decoded.push(remainder as u8);
        input = new_input;
    }

    for _ in 0..zeros {
        decoded.push(0);
    }
    decoded.reverse();
    Ok(decoded)
}

pub fn base58_check_encode(payload: &[u8]) -> String {
    let checksum = &sha256d(payload)[..4];
    let mut extended = payload.to_vec();
    extended.extend_from_slice(checksum);
    base58_encode(&extended)
}

pub fn base58_check_decode(s: &str) -> Result<Vec<u8>, Base58Error> {
    let raw = base58_decode(s)?;
    if raw.len() < 4 {
        return Err(Base58Error::InvalidLength);
    }
    let payload_len = raw.len() - 4;
    let (payload, checksum) = raw.split_at(payload_len);
    let calc_checksum = &sha256d(payload)[..4];
    if calc_checksum != checksum {
        return Err(Base58Error::InvalidChecksum);
    }
    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zeroes() {
        assert_eq!(base58_encode(&[0]), "1");
        assert_eq!(base58_encode(&[0, 0, 1]), "112");
        assert_eq!(base58_encode(&[0, 1]), "12");
        assert_eq!(base58_encode(&[0, 0, 0, 1]), "1112");
        assert_eq!(base58_encode(&[0, 0, 0, 0, 1]), "11112");
        assert_eq!(base58_encode(&[0, 0, 0, 0, 0, 1]), "111112");
        assert_eq!(base58_decode("112").unwrap(), vec![0, 0, 1]);
    }

    #[test]
    fn test_known_vectors() {
        assert_eq!(base58_encode(&[0x00]), "1");
        assert_eq!(base58_encode(&[0x61]), "2g");
        assert_eq!(base58_encode(&[0x62, 0x62, 0x62]), "a3gV");
        assert_eq!(base58_encode(&[0x63, 0x63, 0x63]), "aPEr");
    }

    #[test]
    fn test_base58_decode_empty() {
        let input = "";
        let expected = Err(Base58Error::InvalidLength);
        assert_eq!(base58_decode(input), expected);
    }

    #[test]
    fn test_base58_decode_single_character() {
        let input = "2";
        let expected = Ok(vec![1]);
        assert_eq!(base58_decode(input), expected);
    }

    #[test]
    fn test_base58_decode_multiple_characters() {
        let input = "Ldp";
        let expected = Ok(vec![1, 2, 3]);
        assert_eq!(base58_decode(input), expected);
    }

    #[test]
    fn test_base58_decode_leading_zeros() {
        let input = "5T";
        let expected = Ok(vec![1, 2]);
        assert_eq!(base58_decode(input), expected);
        let input = "15T";
        let expected = Ok(vec![0, 1, 2]);
        assert_eq!(base58_decode(input), expected);
        let input = "1115T";
        let expected = Ok(vec![0, 0, 0, 1, 2]);
        assert_eq!(base58_decode(input), expected);
        let input = "111115T";
        let expected = Ok(vec![0, 0, 0, 0, 0, 1, 2]);
        assert_eq!(base58_decode(input), expected);
    }

    #[test]
    fn test_base58_decode_invalid_character() {
        let input = "4P1e!";
        let expected = Err(Base58Error::InvalidCharacter('!'));
        assert_eq!(base58_decode(input), expected);
    }

    #[test]
    fn test_base58_decode_large_input() {
        let input = "4P1e".repeat(1024);
        let expected = base58_decode(&input);
        assert!(expected.is_ok());
    }

    #[test]
    fn test_decode_invalid_char() {
        match base58_decode("0OIl") {
            Err(Base58Error::InvalidCharacter(c)) => assert_eq!(c, '0'),
            _ => panic!("Expected InvalidCharacter error"),
        }
    }

    #[test]
    fn test_base58_roundtrip1() {
        let data = b"hello world";
        let encoded = base58_encode(data);
        let decoded = base58_decode(&encoded).expect("Base58Check decode failed");
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_base58_roundtrip2() {
        let payload = b"Base58Check";
        let encoded = base58_check_encode(payload);
        let decoded = base58_check_decode(&encoded).expect("Base58Check decode failed");
        assert_eq!(&decoded, payload);
    }

    #[test]
    fn test_base58_roundtrip3() {
        let original = vec![1, 2, 3];
        let encoded = base58_encode(&original);
        let decoded = base58_decode(&encoded);
        assert_eq!(decoded, Ok(original));
    }

    #[test]
    fn test_base58_check_roundtrip() {
        let payload = b"Hello, World!";
        let encoded = base58_check_encode(payload);
        let decoded = base58_check_decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_base58_check_decode_invalid_checksum() {
        let payload = b"Hello, World!";
        let mut encoded = base58_check_encode(payload).into_bytes();
        encoded[0] ^= 1; // flip a bit to make the checksum invalid
        let decoded = base58_check_decode(std::str::from_utf8(&encoded).unwrap());
        assert!(decoded.is_err());
    }

    #[test]
    fn test_base58_check_decode_too_short() {
        let payload = b"Hello";
        let encoded = base58_check_encode(payload);
        let decoded = base58_check_decode(&encoded[..encoded.len() - 1]);
        assert!(decoded.is_err());
    }

    #[test]
    fn test_base58_check_decode_invalid_base58() {
        let payload = b"Hello, World!";
        let mut encoded = base58_check_encode(payload).into_bytes();
        encoded[0] = b'!'; // replace a base58 character with a non-base58 character
        let decoded = base58_check_decode(std::str::from_utf8(&encoded).unwrap());
        assert!(decoded.is_err());
    }

    #[test]
    fn test_base58_check_encode_decode_empty_payload() {
        let payload = b"";
        let encoded = base58_check_encode(payload);
        let decoded = base58_check_decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_base58_check_encode_decode_payload_len_1() {
        let payload = b"a";
        let encoded = base58_check_encode(payload);
        let decoded = base58_check_decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }
}
