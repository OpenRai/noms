//! Bounded deterministic parser/curve fuzz campaign; test-only executable.
use noms::*;
use std::time::{Duration, Instant};

fn next(state: &mut u64) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state as u8
}

fn main() {
    let seconds: u64 = std::env::var("NOMS_FUZZ_SECONDS")
        .unwrap_or_else(|_| "120".into())
        .parse()
        .expect("fuzz duration");
    let seed: u64 = std::env::var("NOMS_TEST_SEED")
        .unwrap_or_else(|_| "1313819987".into())
        .parse()
        .expect("fuzz seed");
    let mut state = seed;
    let started = Instant::now();
    let mut iterations = 0u64;
    while started.elapsed() < Duration::from_secs(seconds) {
        let mut bytes = [0u8; 128];
        for byte in &mut bytes {
            *byte = next(&mut state);
        }
        let text = String::from_utf8_lossy(&bytes);
        let _ = parse_private_key(&text);
        let _ = parse_signature(&text);
        let _ = public_key_from_account(&text);
        let prefix = (next(&mut state) as usize) % 128;
        let message = String::from_utf8_lossy(&bytes[..prefix]);
        let digest = hash_message(&message).expect("valid Unicode fits limit");
        assert_eq!(digest.len(), 32);
        let mut public = [0; 32];
        public.copy_from_slice(&bytes[..32]);
        let account = account_from_public_key(&public);
        assert_eq!(public_key_from_account(&account).unwrap(), public);
        let mut signature = [0; 64];
        signature.copy_from_slice(&bytes[32..96]);
        assert!(
            !verify_message(&message, &signature, &account).expect("well-encoded random material")
        );
        iterations += 1;
    }
    println!("{{\"seed\":{seed},\"iterations\":{iterations},\"seconds\":{seconds}}}");
}
