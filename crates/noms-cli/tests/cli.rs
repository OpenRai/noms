use std::io::Write;
use std::process::{Command, Stdio};

const TEST_PRIVATE_KEY: &str = "681fd5ed71a9f81e9d29e3450f6cd8aacb87346fd21a26003389290b9d0cb173";
const TEST_ACCOUNT: &str = "nano_3noms9a1zytox399kygpge6cc7hu1z79ms1cgzojodz8741qi7w5u3nzb8mn";
const TEST_MESSAGE: &str = "Hej Nano!🥦";

#[test]
fn cli_signs_from_stdin_and_emits_signature_only() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_noms"))
        .args(["sign", "--key-stdin", "--message", TEST_MESSAGE])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(TEST_PRIVATE_KEY.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    assert_eq!(
        String::from_utf8(result.stdout).unwrap().trim(),
        "535c745819d0f40056f3c46402b4fae4356b3a8897bde99c955d411920e740d781e6dddcbde228e8b86c4383a1003f9f315519ff73bd356f561d19865dc90f09"
    );
}

#[test]
fn cli_verifies_piped_signature_and_returns_expected_exit_status() {
    let signature = "535c745819d0f40056f3c46402b4fae4356b3a8897bde99c955d411920e740d781e6dddcbde228e8b86c4383a1003f9f315519ff73bd356f561d19865dc90f09";
    let mut child = Command::new(env!("CARGO_BIN_EXE_noms"))
        .args([
            "verify",
            "--account",
            TEST_ACCOUNT,
            "--signature-stdin",
            "--message",
            TEST_MESSAGE,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(signature.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), "valid");

    let result = Command::new(env!("CARGO_BIN_EXE_noms"))
        .args([
            "verify",
            "--account",
            TEST_ACCOUNT,
            "--signature",
            &"00".repeat(64),
            "--message",
            TEST_MESSAGE,
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), "invalid");
}

#[test]
fn inspect_preserves_trailing_newline_from_message_stdin() {
    let result = Command::new(env!("CARGO_BIN_EXE_noms"))
        .args(["inspect", "--message-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = result;
    child.stdin.take().unwrap().write_all(b"line\r\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("utf8_bytes: 6")
    );
}
