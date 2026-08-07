# global-crypto

A globally-callable cryptographic abstraction layer for Rust, inspired by
`embassy-time`. No `&mut` plumbing required — just call crypto functions
from anywhere.

Most of this is LLM generated code. This repository will never contain implementations
of any algorithm other than the embedded-cal abstraction. The principle function of
this code is to hand off to the `CryptoDriver` as quickly as possible.

## Architecture

```
┌─────────────────────────────────────────┐
│  User code calls global free functions  │
│  e.g. global_crypto::sync_api::hash()   │
├─────────────────────────────────────────┤
│  Rich types: AeadKey<A>, Tag<A>, etc.   │
├─────────────────────────────────────────┤
│  Registry (critical-section + heapless) │
│  selects best dyn CryptoDriver          │
├─────────────────────────────────────────┤
│  dyn CryptoDriver trait (object-safe)   │
│  &self, enum algorithms, slice buffers  │
├─────────────────────────────────────────┤
│  EmbeddedCalBridge<C: Cal>              │
│  Mutex<RefCell<C>> for &mut → &self     │
├─────────────────────────────────────────┤
│  embedded-cal rich types & traits       │
│  (associated types, impl Trait, etc.)   │
└─────────────────────────────────────────┘
```

## Crates

- **`global-crypto`** — Core registry, dyn-safe `CryptoDriver` trait, rich
  algorithm/data types, and global sync/async APIs.
- **`global-crypto-embedded-cal`** — Bridge that wraps any `embedded-cal::Cal`
  implementation behind `dyn CryptoDriver`.

## Usage

```rust
use embedded_cal::empty::EmptyCal;
use global_crypto::{register_provider, ProviderEntry, Sha256};
use global_crypto_embedded_cal::EmbeddedCalBridge;

static BRIDGE: EmbeddedCalBridge<EmptyCal> = EmbeddedCalBridge::new(EmptyCal);

fn init() {
    register_provider(ProviderEntry {
        driver: &BRIDGE,
        priority: 0,
    });
}

fn somewhere_else() {
    let digest = global_crypto::sync_api::hash::<Sha256>(b"hello").unwrap();
}
```

## Features

- **No `&mut` plumbing** — call crypto from any context
- **Rich types above** — `AeadKey<AesCcm16_64_128>`, `Tag<AesGcm256>`, etc.
- **Rich types below** — bridge uses `C::AeadProvider::Key`, `C::HashProvider::Output`
- **Dyn-safe registry** — multiple providers with priority-based selection
- **Async-ready** — `AsyncCryptoDriver` trait for interrupt-driven HW accelerators
- **`no_std` + `no_alloc`** — uses `heapless` and `critical-section`

## License

MIT OR Apache-2.0
