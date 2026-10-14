# noms

Rust reference implementation of NOMS as specified by ORIS-001.

```rust
use noms::{account_from_public_key, parse_private_key, sign_message, verify_message};

let private_key = parse_private_key("681fd5ed71a9f81e9d29e3450f6cd8aacb87346fd21a26003389290b9d0cb173")?;
let signature = sign_message("Hej Nano!🥦", &private_key)?;
let account = account_from_public_key(&noms::public_key_from_private_key(&private_key));
assert!(verify_message("Hej Nano!🥦", &signature, &account)?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The key is a raw 32-byte Nano account private key, not a wallet seed. The crate validates lowercase `nano_` and legacy `xrb_` account addresses, including their checksum. Message bytes are exact UTF-8 with no normalization. The implementation enforces a 16 MiB message limit.
