#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Rust reference implementation of Nano Off-chain Message Signing (ORIS-001).

use blake2b_simd::Params;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
    traits::IsIdentity,
};
use std::{error::Error, fmt};

const HEADER: &[u8; 25] = b"\x18Nano Off-chain Message:\n";
const BASE32: &[u8; 32] = b"13456789abcdefghijkmnopqrstuwxyz";
/// Maximum message size accepted by this implementation (16 MiB).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// Errors returned for malformed inputs or invalid cryptographic material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NomsError(pub String);

impl fmt::Display for NomsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl Error for NomsError {}

fn invalid(message: &str) -> NomsError {
    NomsError(message.to_owned())
}

/// Constructs `MAGIC_HEADER || uint32_be(UTF8_length) || UTF8(message)`.
pub fn encode_payload(message: &str) -> Result<Vec<u8>, NomsError> {
    let bytes = message.as_bytes();
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(invalid("message exceeds the 16 MiB implementation limit"));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| invalid("message exceeds the uint32 length limit"))?;
    let mut payload = Vec::with_capacity(HEADER.len() + 4 + bytes.len());
    payload.extend_from_slice(HEADER);
    payload.extend_from_slice(&length.to_be_bytes());
    payload.extend_from_slice(bytes);
    Ok(payload)
}

/// Computes the 32-byte Blake2b digest of the ORIS-001 payload.
pub fn hash_message(message: &str) -> Result<[u8; 32], NomsError> {
    let payload = encode_payload(message)?;
    let hash = Params::new().hash_length(32).hash(&payload);
    let mut output = [0; 32];
    output.copy_from_slice(hash.as_bytes());
    Ok(output)
}

fn hash512(bytes: &[u8]) -> [u8; 64] {
    let hash = Params::new().hash_length(64).hash(bytes);
    let mut output = [0; 64];
    output.copy_from_slice(hash.as_bytes());
    output
}

fn expanded_secret(private_key: &[u8; 32]) -> ([u8; 64], Scalar) {
    let digest = hash512(private_key);
    let mut scalar_bytes = [0; 32];
    scalar_bytes.copy_from_slice(&digest[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 63;
    scalar_bytes[31] |= 64;
    (digest, Scalar::from_bytes_mod_order(scalar_bytes))
}

/// Derives a Nano account public key from a raw 32-byte account private key.
pub fn public_key_from_private_key(private_key: &[u8; 32]) -> [u8; 32] {
    let (_, scalar) = expanded_secret(private_key);
    (scalar * ED25519_BASEPOINT_POINT).compress().to_bytes()
}

/// Signs the NOMS digest using Nano's Ed25519-BLAKE2b account-signing scheme.
pub fn sign_message(message: &str, private_key: &[u8; 32]) -> Result<[u8; 64], NomsError> {
    let digest = hash_message(message)?;
    let (expanded, secret_scalar) = expanded_secret(private_key);
    let mut nonce_input = Vec::with_capacity(32 + digest.len());
    nonce_input.extend_from_slice(&expanded[32..]);
    nonce_input.extend_from_slice(&digest);
    let nonce_hash = hash512(&nonce_input);
    let nonce = Scalar::from_bytes_mod_order_wide(&nonce_hash);
    let encoded_r = (nonce * ED25519_BASEPOINT_POINT).compress().to_bytes();
    let public_key = public_key_from_private_key(private_key);

    let mut challenge_input = Vec::with_capacity(64 + digest.len());
    challenge_input.extend_from_slice(&encoded_r);
    challenge_input.extend_from_slice(&public_key);
    challenge_input.extend_from_slice(&digest);
    let challenge = Scalar::from_bytes_mod_order_wide(&hash512(&challenge_input));
    let encoded_s = (nonce + challenge * secret_scalar).to_bytes();

    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&encoded_r);
    signature[32..].copy_from_slice(&encoded_s);
    Ok(signature)
}

/// Verifies a NOMS signature against a Nano account address (`nano_` or `xrb_`).
pub fn verify_message(
    message: &str,
    signature: &[u8; 64],
    account: &str,
) -> Result<bool, NomsError> {
    let public_key = public_key_from_account(account)?;
    let r_bytes: [u8; 32] = signature[..32].try_into().expect("fixed signature slice");
    let s_bytes: [u8; 32] = signature[32..].try_into().expect("fixed signature slice");
    let Some(scalar_s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return Ok(false);
    };
    let Some(point_r) = CompressedEdwardsY(r_bytes).decompress() else {
        return Ok(false);
    };
    let Some(point_a) = CompressedEdwardsY(public_key).decompress() else {
        return Ok(false);
    };
    if point_a.is_identity() || point_r.is_identity() {
        return Ok(false);
    }

    let digest = hash_message(message)?;
    let mut challenge_input = Vec::with_capacity(64 + digest.len());
    challenge_input.extend_from_slice(&r_bytes);
    challenge_input.extend_from_slice(&public_key);
    challenge_input.extend_from_slice(&digest);
    let challenge = Scalar::from_bytes_mod_order_wide(&hash512(&challenge_input));
    Ok(scalar_s * ED25519_BASEPOINT_POINT == point_r + challenge * point_a)
}

fn base32_value(byte: u8) -> Option<u8> {
    BASE32
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|i| i as u8)
}

fn encode_base32(bytes: &[u8], leading_padding_bits: usize, digits: usize) -> String {
    let mut out = String::with_capacity(digits);
    for digit in 0..digits {
        let mut value = 0u8;
        for within in 0..5 {
            let stream_bit = digit * 5 + within;
            value <<= 1;
            if stream_bit >= leading_padding_bits {
                let bit = stream_bit - leading_padding_bits;
                if bit < bytes.len() * 8 {
                    value |= (bytes[bit / 8] >> (7 - bit % 8)) & 1;
                }
            }
        }
        out.push(BASE32[value as usize] as char);
    }
    out
}

fn decode_base32(
    text: &str,
    output: &mut [u8],
    leading_padding_bits: usize,
) -> Result<(), NomsError> {
    for (digit, byte) in text.bytes().enumerate() {
        let value = base32_value(byte)
            .ok_or_else(|| invalid("account contains invalid Nano base32 characters"))?;
        for within in 0..5 {
            let stream_bit = digit * 5 + within;
            let bit_value = (value >> (4 - within)) & 1;
            if stream_bit < leading_padding_bits {
                if bit_value != 0 {
                    return Err(invalid("account contains nonzero padding bits"));
                }
            } else {
                let bit = stream_bit - leading_padding_bits;
                if bit >= output.len() * 8 {
                    if bit_value != 0 {
                        return Err(invalid("account value exceeds its encoded width"));
                    }
                } else if bit_value != 0 {
                    output[bit / 8] |= 1 << (7 - bit % 8);
                }
            }
        }
    }
    Ok(())
}

/// Encodes a public key as its canonical lowercase Nano account address.
pub fn account_from_public_key(public_key: &[u8; 32]) -> String {
    let checksum_hash = Params::new().hash_length(5).hash(public_key);
    let mut checksum = checksum_hash.as_bytes().to_vec();
    checksum.reverse();
    format!(
        "nano_{}{}",
        encode_base32(public_key, 4, 52),
        encode_base32(&checksum, 0, 8)
    )
}

/// Decodes and checksum-validates a lowercase `nano_` or `xrb_` account.
pub fn public_key_from_account(account: &str) -> Result<[u8; 32], NomsError> {
    let encoded = account
        .strip_prefix("nano_")
        .or_else(|| account.strip_prefix("xrb_"))
        .ok_or_else(|| invalid("account must use the nano_ or xrb_ prefix"))?;
    if encoded.len() != 60 {
        return Err(invalid(
            "account must contain exactly 60 Nano base32 characters",
        ));
    }
    let (key_text, checksum_text) = encoded.split_at(52);
    let mut public_key = [0; 32];
    decode_base32(key_text, &mut public_key, 4)?;
    let mut supplied_checksum = [0; 5];
    decode_base32(checksum_text, &mut supplied_checksum, 0)?;
    supplied_checksum.reverse();
    let expected = Params::new().hash_length(5).hash(&public_key);
    if supplied_checksum.as_slice() != expected.as_bytes() {
        return Err(invalid("account checksum is invalid"));
    }
    Ok(public_key)
}

/// Parses exactly 64 hexadecimal characters as a private key.
pub fn parse_private_key(hex: &str) -> Result<[u8; 32], NomsError> {
    parse_hex(hex, "private key")
}

/// Parses exactly 128 hexadecimal characters as a signature.
pub fn parse_signature(hex: &str) -> Result<[u8; 64], NomsError> {
    parse_hex(hex, "signature")
}

fn parse_hex<const N: usize>(hex: &str, field: &str) -> Result<[u8; N], NomsError> {
    if hex.len() != N * 2 {
        return Err(invalid(&format!(
            "{field} must be exactly {} hexadecimal characters",
            N * 2
        )));
    }
    let mut bytes = [0; N];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid(&format!("{field} contains non-hexadecimal characters")))?;
    }
    Ok(bytes)
}

/// Encodes bytes as lowercase hexadecimal.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

    #[test]
    fn published_vectors_match_and_cross_verify() {
        let vector_path = format!(
            "{}/../../conformance/vectors.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let vectors: Value =
            serde_json::from_str(&fs::read_to_string(vector_path).unwrap()).unwrap();
        let key = parse_private_key(vectors["keypair"]["private_key"].as_str().unwrap()).unwrap();
        let account = vectors["keypair"]["account"].as_str().unwrap();
        assert_eq!(
            to_hex(&public_key_from_private_key(&key)),
            vectors["keypair"]["public_key"].as_str().unwrap()
        );
        for vector in vectors["vectors"].as_array().unwrap() {
            let message = vector["message"].as_str().unwrap();
            let expected_payload = vector["payload_hex"].as_str().unwrap();
            let expected_digest = vector["digest"].as_str().unwrap();
            let expected_signature = vector["signature"].as_str().unwrap();
            assert_eq!(to_hex(&encode_payload(message).unwrap()), expected_payload);
            assert_eq!(to_hex(&hash_message(message).unwrap()), expected_digest);
            let signature = sign_message(message, &key).unwrap();
            assert_eq!(to_hex(&signature), expected_signature);
            assert!(verify_message(message, &signature, account).unwrap());
        }
    }

    #[test]
    fn exact_text_changes_the_digest() {
        let vector_path = format!(
            "{}/../../conformance/cases.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let cases: Value = serde_json::from_str(&fs::read_to_string(vector_path).unwrap()).unwrap();
        let messages = cases["boundary_messages"].as_array().unwrap();
        let hashes: Vec<_> = messages
            .iter()
            .map(|message| hash_message(message.as_str().unwrap()).unwrap())
            .collect();
        let unique: std::collections::HashSet<_> = hashes.iter().collect();
        assert_eq!(unique.len(), messages.len());
    }

    #[test]
    fn rejects_modified_message_and_bad_account() {
        let key =
            parse_private_key("681fd5ed71a9f81e9d29e3450f6cd8aacb87346fd21a26003389290b9d0cb173")
                .unwrap();
        let signature = sign_message("Hej Nano!🥦", &key).unwrap();
        let account = account_from_public_key(&public_key_from_private_key(&key));
        assert!(!verify_message("changed", &signature, &account).unwrap());
        let mut altered = signature;
        altered[63] ^= 1;
        assert!(!verify_message("Hej Nano!🥦", &altered, &account).unwrap());
        assert!(public_key_from_account("nano_invalid").is_err());
    }
}
