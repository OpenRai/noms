use noms::{parse_private_key, sign_message, to_hex};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = parse_private_key(&std::env::var("NANO_ACCOUNT_PRIVATE_KEY")?)?;
    let signature = sign_message("NOMS example challenge", &key)?;
    println!("{}", to_hex(&signature));
    Ok(())
}
