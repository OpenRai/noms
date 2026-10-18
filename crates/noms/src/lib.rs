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

/// Parses an exact ORIS-001 frame and returns its UTF-8 message.
pub fn parse_payload(payload: &[u8]) -> Result<String, NomsError> {
    if payload.len() < HEADER.len() + 4 {
        return Err(invalid("payload is a truncated NOMS frame"));
    }
    if &payload[..HEADER.len()] != HEADER {
        return Err(invalid("payload has an invalid NOMS header"));
    }
    let message_length = u32::from_be_bytes(
        payload[HEADER.len()..HEADER.len() + 4]
            .try_into()
            .map_err(|_| invalid("payload is a truncated NOMS frame"))?,
    ) as usize;
    if message_length > MAX_MESSAGE_BYTES {
        return Err(invalid("message exceeds the 16 MiB implementation limit"));
    }
    let message_start = HEADER.len() + 4;
    if payload.len() != message_start + message_length {
        return Err(invalid("payload length does not match the NOMS frame"));
    }
    std::str::from_utf8(&payload[message_start..])
        .map(str::to_owned)
        .map_err(|_| invalid("payload message is not valid UTF-8"))
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
    if nonce == Scalar::ZERO {
        return Err(invalid("derived signing nonce is zero"));
    }
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

// Canonical decoding is separate from subgroup membership so both rules can
// be checked directly, even when another validation would reject the input.
fn decode_canonical_point(bytes: [u8; 32]) -> Option<curve25519_dalek::edwards::EdwardsPoint> {
    let point = CompressedEdwardsY(bytes).decompress()?;
    if point.compress().to_bytes() != bytes {
        return None;
    }
    Some(point)
}

/// Verifies a NOMS signature against a Nano account using strict ORIS-001 rules.
pub fn verify_message(
    message: &str,
    signature: &[u8; 64],
    account: &str,
) -> Result<bool, NomsError> {
    let public_key = public_key_from_account(account)?;
    let digest = hash_message(message)?;
    let mut r_bytes = [0; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let Some(scalar_s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) else {
        return Ok(false);
    };
    let Some(point_r) = decode_canonical_point(r_bytes) else {
        return Ok(false);
    };
    let Some(point_a) = decode_canonical_point(public_key) else {
        return Ok(false);
    };
    if point_a.is_identity()
        || point_r.is_identity()
        || !point_a.is_torsion_free()
        || !point_r.is_torsion_free()
    {
        return Ok(false);
    }

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
    if encoded.len() != 60 || !encoded.is_ascii() {
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
    if hex.len() != N * 2 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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

    #[test]
    fn published_vectors_match_and_cross_verify() {
        let suite: Value = serde_json::from_str(include_str!("../tests/data/suite.json")).unwrap();
        let cases = suite["cases"].as_array().unwrap();
        let first = cases.iter().find(|test| test["id"] == "key-0").unwrap();
        let key = parse_private_key(first["input"]["private_key"].as_str().unwrap()).unwrap();
        let account = first["expected"]["account"].as_str().unwrap();
        assert_eq!(
            to_hex(&public_key_from_private_key(&key)),
            first["expected"]["public_key"].as_str().unwrap()
        );
        for vector in cases
            .iter()
            .filter(|test| test["operation"] == "inspect" && test["input"]["message"].is_string())
        {
            let message = vector["input"]["message"].as_str().unwrap();
            let expected_payload = vector["expected"]["payload_hex"].as_str().unwrap();
            let expected_digest = vector["expected"]["digest"].as_str().unwrap();
            let signing = cases
                .iter()
                .find(|test| {
                    test["operation"] == "sign"
                        && test["input"]["message"] == message
                        && test["input"]["private_key"] == first["input"]["private_key"]
                })
                .unwrap();
            let expected_signature = signing["expected"]["signature"].as_str().unwrap();
            assert_eq!(to_hex(&encode_payload(message).unwrap()), expected_payload);
            assert_eq!(to_hex(&hash_message(message).unwrap()), expected_digest);
            let signature = sign_message(message, &key).unwrap();
            assert_eq!(to_hex(&signature), expected_signature);
            assert!(verify_message(message, &signature, account).unwrap());
        }
    }

    #[test]
    fn shared_framed_input_cases_match() {
        let suite: Value = serde_json::from_str(include_str!("../tests/data/suite.json")).unwrap();
        for test in suite["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|test| test["operation"] == "parse_frame")
        {
            let input = test["input"]["payload_hex"].as_str().unwrap();
            let bytes: Vec<_> = input
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16))
                .collect::<Result<_, _>>()
                .unwrap();
            assert!(parse_payload(&bytes).is_err(), "{}", test["id"]);
            assert_eq!(test["expected"]["status"], "input_error", "{}", test["id"]);
        }
    }

    #[test]
    fn framed_payload_round_trips_exact_utf8() {
        let message = "nano\0e\u{301} 🥦";
        assert_eq!(
            parse_payload(&encode_payload(message).unwrap()).unwrap(),
            message
        );
    }

    #[test]
    fn exact_text_changes_the_digest() {
        let cases: Value = serde_json::from_str(include_str!("../tests/data/suite.json")).unwrap();
        let messages: Vec<_> = cases["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|test| test["operation"] == "inspect" && test["input"]["message"].is_string())
            .map(|test| &test["input"]["message"])
            .collect();
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

    #[test]
    fn rejects_malformed_key_signature_and_account_inputs() {
        assert!(parse_private_key("00").is_err());
        assert!(parse_signature(&"zz".repeat(64)).is_err());
        assert!(public_key_from_account(
            "nano_3noms9a1zytox399kygpge6cc7hu1z79ms1cgzojodz8741qi7w5u3nzb8mn "
        )
        .is_err());
    }

    #[test]
    fn canonical_decoder_rejects_alias_before_subgroup_checks() {
        let mut alias = [255; 32];
        alias[0] = 0xee;
        alias[31] = 0x7f;
        assert!(decode_canonical_point(alias).is_none());
    }

    #[test]
    fn enforces_exact_size_boundary() {
        assert_eq!(
            encode_payload(&"a".repeat(MAX_MESSAGE_BYTES))
                .unwrap()
                .len(),
            MAX_MESSAGE_BYTES + 29
        );
        assert!(encode_payload(&"a".repeat(MAX_MESSAGE_BYTES + 1)).is_err());
    }

    #[test]
    fn shared_adversarial_verification_corpus() {
        let suite: Value = serde_json::from_str(include_str!("../tests/data/suite.json")).unwrap();
        for test in suite["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|test| test["operation"] == "verify")
        {
            let input = &test["input"];
            let result =
                parse_signature(input["signature"].as_str().unwrap()).and_then(|signature| {
                    verify_message(
                        input["message"].as_str().unwrap(),
                        &signature,
                        input["account"].as_str().unwrap(),
                    )
                });
            let status = match result {
                Ok(true) => "valid",
                Ok(false) => "invalid",
                Err(_) => "input_error",
            };
            assert_eq!(
                status,
                test["expected"]["status"].as_str().unwrap(),
                "{}",
                test["id"]
            );
        }
    }
}
