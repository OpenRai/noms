//! Test-only JSON-lines adapter. Not installed or exported by the library.
use noms::*;
use serde_json::{Value, json};
use std::io::{self, BufRead};

fn input_error() -> NomsError {
    NomsError("malformed adapter input".to_owned())
}

fn text<'a>(input: &'a Value, name: &str) -> Result<&'a str, NomsError> {
    input[name].as_str().ok_or_else(input_error)
}

fn bytes(hex: &str) -> Result<Vec<u8>, NomsError> {
    if !hex.is_ascii() || !hex.len().is_multiple_of(2) {
        return Err(input_error());
    }
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let value = std::str::from_utf8(pair).map_err(|_| input_error())?;
            u8::from_str_radix(value, 16).map_err(|_| input_error())
        })
        .collect()
}

fn message(input: &Value) -> Result<String, NomsError> {
    if let Some(value) = input["message"].as_str() {
        return Ok(value.to_owned());
    }
    if let Some(value) = input["message_utf8_hex"].as_str() {
        return String::from_utf8(bytes(value)?).map_err(|_| input_error());
    }
    if let Some(units) = input["message_utf16"].as_array() {
        let units: Result<Vec<_>, _> = units
            .iter()
            .map(|unit| {
                u16::try_from(unit.as_u64().ok_or_else(input_error)?).map_err(|_| input_error())
            })
            .collect();
        return String::from_utf16(&units?).map_err(|_| input_error());
    }
    let repeat = &input["message_repeat"];
    let count = usize::try_from(repeat["count"].as_u64().ok_or_else(input_error)?)
        .map_err(|_| input_error())?;
    if count > MAX_MESSAGE_BYTES + 1 {
        return Err(input_error());
    }
    Ok(text(repeat, "text")?.repeat(count))
}

fn run(test: &Value) -> Result<Value, NomsError> {
    let input = &test["input"];
    match text(test, "operation")? {
        "parse_frame" => {
            let payload = bytes(text(input, "payload_hex")?)?;
            parse_payload(&payload)?;
            Ok(json!({"status":"ok"}))
        }
        "derive" => {
            let key = parse_private_key(text(input, "private_key")?)?;
            let public = public_key_from_private_key(&key);
            Ok(
                json!({"status":"ok", "public_key":to_hex(&public), "account":account_from_public_key(&public)}),
            )
        }
        "inspect" => {
            let message = message(input)?;
            let payload = encode_payload(&message)?;
            Ok(
                json!({"status":"ok", "message_utf8_hex":to_hex(message.as_bytes()), "payload_hex":to_hex(&payload), "digest":to_hex(&hash_message(&message)?)}),
            )
        }
        "sign" => {
            let key = parse_private_key(text(input, "private_key")?)?;
            Ok(json!({"status":"ok", "signature":to_hex(&sign_message(&message(input)?, &key)?)}))
        }
        "verify" => {
            let signature = parse_signature(text(input, "signature")?)?;
            let valid = verify_message(&message(input)?, &signature, text(input, "account")?)?;
            Ok(json!({"status":if valid { "valid" } else { "invalid" }}))
        }
        _ => Err(input_error()),
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("adapter stdin");
        let test: Value = serde_json::from_str(&line).expect("adapter JSON");
        let mut result = run(&test).unwrap_or_else(|_| json!({"status":"input_error"}));
        result["id"] = test["id"].clone();
        println!("{result}");
    }
}
