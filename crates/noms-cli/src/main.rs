#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use noms::{
    encode_payload, hash_message, parse_private_key, parse_signature, sign_message, to_hex,
    verify_message,
};
use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

mod self_test_vectors;
use self_test_vectors::*;

#[derive(Debug, Parser)]
#[command(
    name = "noms",
    version,
    about = "Nano Off-chain Message Signing (ORIS-001)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Sign an exact UTF-8 message with a raw Nano account private key.
    Sign {
        #[arg(long, conflicts_with_all = ["key_stdin", "prompt_key"])]
        key_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "prompt_key")]
        key_stdin: bool,
        #[arg(long)]
        prompt_key: bool,
        #[arg(
            long,
            allow_hyphen_values = true,
            required_unless_present = "message_stdin",
            conflicts_with = "message_stdin"
        )]
        message: Option<String>,
        #[arg(long)]
        message_stdin: bool,
    },
    /// Verify a signature against the exact message and Nano account.
    Verify {
        #[arg(long)]
        account: String,
        #[arg(long, conflicts_with = "signature_stdin")]
        signature: Option<String>,
        #[arg(long)]
        signature_stdin: bool,
        #[arg(
            long,
            allow_hyphen_values = true,
            required_unless_present = "message_stdin",
            conflicts_with = "message_stdin"
        )]
        message: Option<String>,
        #[arg(long)]
        message_stdin: bool,
    },
    /// Display the ORIS-001 payload bytes and digest for a message.
    Inspect {
        #[arg(
            long,
            allow_hyphen_values = true,
            required_unless_present = "message_stdin",
            conflicts_with = "message_stdin"
        )]
        message: Option<String>,
        #[arg(long)]
        message_stdin: bool,
    },
    /// Check built-in known-answer vectors without network access.
    SelfTest,
}

fn read_bounded(reader: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read standard input: {error}"))?;
    if bytes.len() > limit {
        return Err("input exceeds the implementation size limit".to_owned());
    }
    Ok(bytes)
}

fn read_message(message: Option<String>, from_stdin: bool) -> Result<String, String> {
    let bytes = if from_stdin {
        read_bounded(io::stdin(), noms::MAX_MESSAGE_BYTES)?
    } else {
        message
            .ok_or_else(|| "provide --message TEXT or --message-stdin".to_owned())?
            .into_bytes()
    };
    String::from_utf8(bytes).map_err(|_| "message input must be valid UTF-8".to_owned())
}

fn read_key(path: Option<PathBuf>, from_stdin: bool, prompt: bool) -> Result<String, String> {
    let value = if let Some(path) = path {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata =
                fs::metadata(&path).map_err(|error| format!("cannot read key file: {error}"))?;
            if metadata.mode() & 0o077 != 0 {
                return Err(
                    "key file permissions must exclude group and other access (use chmod 600)"
                        .to_owned(),
                );
            }
        }
        let file =
            fs::File::open(path).map_err(|error| format!("cannot read key file: {error}"))?;
        String::from_utf8(read_bounded(file, 4096)?)
            .map_err(|_| "key input must be UTF-8 hexadecimal".to_owned())?
    } else if from_stdin {
        String::from_utf8(read_bounded(io::stdin(), 4096)?)
            .map_err(|_| "key input must be UTF-8 hexadecimal".to_owned())?
    } else if prompt {
        if !io::stdin().is_terminal() {
            return Err("--prompt-key requires an interactive terminal".to_owned());
        }
        rpassword::prompt_password("Nano account private key (hex): ")
            .map_err(|error| format!("could not read hidden key prompt: {error}"))?
    } else {
        return Err("provide --key-file PATH, --key-stdin, or --prompt-key; never pass a private key as an argument".to_owned());
    };
    Ok(trim_envelope(&value).to_owned())
}

fn trim_envelope(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'))
}

fn run(command: Command) -> Result<bool, String> {
    match command {
        Command::Sign {
            key_file,
            key_stdin,
            prompt_key,
            message,
            message_stdin,
        } => {
            if (key_stdin || prompt_key) && message_stdin {
                return Err("standard input cannot supply both the key and the message; use --key-file with --message-stdin".to_owned());
            }
            let key = parse_private_key(&read_key(key_file, key_stdin, prompt_key)?)
                .map_err(|error| error.to_string())?;
            let message = read_message(message, message_stdin)?;
            let signature = sign_message(&message, &key).map_err(|error| error.to_string())?;
            println!("{}", to_hex(&signature));
            Ok(true)
        }
        Command::Verify {
            account,
            signature,
            signature_stdin,
            message,
            message_stdin,
        } => {
            if signature_stdin && message_stdin {
                return Err("standard input cannot supply both the signature and the message; use --message TEXT".to_owned());
            }
            let signature = if signature_stdin {
                let value = String::from_utf8(read_bounded(io::stdin(), 4096)?)
                    .map_err(|_| "signature input must be UTF-8 hexadecimal".to_owned())?;
                trim_envelope(&value).to_owned()
            } else {
                signature
                    .ok_or_else(|| "provide --signature HEX or --signature-stdin".to_owned())?
            };
            let parsed = parse_signature(&signature).map_err(|error| error.to_string())?;
            let message = read_message(message, message_stdin)?;
            let valid =
                verify_message(&message, &parsed, &account).map_err(|error| error.to_string())?;
            println!("{}", if valid { "valid" } else { "invalid" });
            Ok(valid)
        }
        Command::Inspect {
            message,
            message_stdin,
        } => {
            let message = read_message(message, message_stdin)?;
            let payload = encode_payload(&message).map_err(|error| error.to_string())?;
            let digest = hash_message(&message).map_err(|error| error.to_string())?;
            println!(
                "utf8_bytes: {}\npayload: {}\ndigest: {}",
                message.len(),
                to_hex(&payload),
                to_hex(&digest)
            );
            Ok(true)
        }
        Command::SelfTest => {
            let key = parse_private_key(TEST_PRIVATE_KEY).map_err(|error| error.to_string())?;
            let signature = parse_signature(TEST_SIGNATURE).map_err(|error| error.to_string())?;
            let empty_signature =
                parse_signature(EMPTY_SIGNATURE).map_err(|error| error.to_string())?;
            let ok = to_hex(&sign_message(TEST_MESSAGE, &key).map_err(|error| error.to_string())?)
                == TEST_SIGNATURE
                && verify_message(TEST_MESSAGE, &signature, TEST_ACCOUNT)
                    .map_err(|error| error.to_string())?
                && to_hex(&hash_message("").map_err(|error| error.to_string())?) == EMPTY_DIGEST
                && to_hex(&sign_message("", &key).map_err(|error| error.to_string())?)
                    == EMPTY_SIGNATURE
                && verify_message("", &empty_signature, TEST_ACCOUNT)
                    .map_err(|error| error.to_string())?
                && !verify_message(
                    TEST_MESSAGE,
                    &parse_signature(NONCANONICAL_SIGNATURE).map_err(|error| error.to_string())?,
                    TEST_ACCOUNT,
                )
                .map_err(|error| error.to_string())?;
            println!(
                "{}",
                if ok {
                    "NOMS conformance vectors passed"
                } else {
                    "NOMS conformance vectors failed"
                }
            );
            Ok(ok)
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            let _ = writeln!(io::stderr(), "{error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noms::{account_from_public_key, public_key_from_private_key};

    #[test]
    fn signing_test_account_derives_the_published_address() {
        let key = parse_private_key(TEST_PRIVATE_KEY).unwrap();
        let account = account_from_public_key(&public_key_from_private_key(&key));
        assert_eq!(account, TEST_ACCOUNT);
    }

    #[test]
    fn published_vector_verifies() {
        let signature = parse_signature(TEST_SIGNATURE).unwrap();
        assert!(verify_message(TEST_MESSAGE, &signature, TEST_ACCOUNT).unwrap());
    }
}
