# accelerated-crypto

RustCrypto trait implementations ([`digest`], [`cipher`], [`aead`]) backed by
[`embassy-crypto`] (main branch).

Extracted from `embassy-crypto` @ `9f62a8b` and renamed. The original module
patterns are preserved; the only structural change is the backend: where the
original crate dispatched through the `embassy-crypto-driver` unitraits, this
crate wraps the corresponding `embassy-crypto` (main branch) types, which are
themselves served at link time by pluggable drivers. Link a hardware driver
crate (e.g. a HAL) or a software driver crate to decide what actually executes.

## Modules

- `hash` — digests (Md5, Sha1, Sha224/256, Sha384, Sha512, Sha512-224/256) and
  HMACs over them, as RustCrypto `Digest`/`Mac` impls.
- `aes` — Aes128/Aes256 and the CBC, CTR, GCM, CCM and CMAC modes, as
  RustCrypto `BlockCipher*`, `BlockMode*`, `StreamCipher`, `AeadInOut` and
  `Mac` impls.
- `ec` (feature `ec`) — generic `elliptic-curve` trait impls over an
  `embassy-crypto`-accelerated backend. Only the operations that were
  previously accelerated are accelerated: scalar multiplication, inversion and
  `k1*P1 + k2*P2` linear combination. Everything else (field arithmetic,
  point addition/doubling, encodings, validation) stays software via the
  `p256`/`p384` crates.
- `p256` / `p384` (features `p256`, `p384`, plus `-ecdsa` variants and
  `pkcs8`) — the `ec` module instantiated for NIST P-256 / P-384.

The old `driver-*` cargo features are gone: with the new `embassy-crypto`
backend, driver selection happens by linking, not by features.

## Usage

```toml
[dependencies]
accelerated-crypto = { path = "accelerated-crypto" }
# plus a driver provider for the operations you use, e.g. a HAL.
```

```rust,ignore
use accelerated_crypto::Sha256;
use digest::Digest;

let digest = Sha256::digest(b"hello");
```

## Testing

`tests/sha256.rs` registers a small self-contained software driver for
`embassy-crypto`'s SHA-256/HMAC-SHA-256 and runs known-answer vectors through
`accelerated-crypto`'s RustCrypto wrappers:

```
cargo test --test sha256
```

[`embassy-crypto`]: https://github.com/embassy-rs/embassy
