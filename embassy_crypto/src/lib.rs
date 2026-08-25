#![no_std]

pub use embassy_crypto_driver::{
    Algorithm, BlockingOp, ContextHandle, CryptoError, HashContext,
};

// ------------------------------------------------------------------
// Blocking dispatch
// ------------------------------------------------------------------

/// Dispatch a blocking operation to the linked crypto driver.
pub fn dispatch_blocking(op: BlockingOp<'_>) -> Result<(), CryptoError> {
    match embassy_crypto_driver::dispatch_blocking(op) {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(e),
        None => Err(CryptoError::Unsupported),
    }
}

// ------------------------------------------------------------------
// Hash types
// ------------------------------------------------------------------

macro_rules! define_hash {
    ($(#[$meta:meta])* $name:ident, $algo:path, $out:expr) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            handle: ContextHandle,
        }

        impl $name {
            /// Create a new hash context.
            pub fn new() -> Result<Self, CryptoError> {
                let handle = embassy_crypto_driver::try_context_init($algo)?;
                Ok(Self { handle })
            }

            /// Feed more data into the hash.
            pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                embassy_crypto_driver::try_context_update(self.handle, data)
            }

            /// Reset the hash to its initial state.
            pub fn reset(&mut self) -> Result<(), CryptoError> {
                embassy_crypto_driver::try_context_reset(self.handle)
            }

            /// Finalize the hash and write the digest into `out`.
            ///
            /// `out` must be at least [`$name::output_size`] bytes long.
            pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
                embassy_crypto_driver::try_context_finalize(self.handle, out)
            }

            /// Digest length in bytes.
            pub const fn output_size() -> usize {
                $out
            }
        }
    };
}

define_hash!(Sha1, Algorithm::SHA1, 20);
define_hash!(Md5, Algorithm::MD5, 16);
define_hash!(Sha224, Algorithm::SHA224, 28);
define_hash!(Sha256, Algorithm::SHA256, 32);
define_hash!(Sha384, Algorithm::SHA384, 48);
define_hash!(Sha512_224, Algorithm::SHA512_224, 28);
define_hash!(Sha512_256, Algorithm::SHA512_256, 32);
define_hash!(Sha512, Algorithm::SHA512, 64);

// ------------------------------------------------------------------
// HMAC types
// ------------------------------------------------------------------

/// Streaming HMAC-SHA-256 context backed by the linked crypto driver.
#[derive(Clone)]
pub struct HmacSha256 {
    handle: ContextHandle,
}

impl HmacSha256 {
    /// Create a new HMAC-SHA-256 context with the given key.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
        let handle = embassy_crypto_driver::try_context_init(Algorithm::HmacSha256 { key })?;
        Ok(Self { handle })
    }

    /// Feed more data into the HMAC.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        embassy_crypto_driver::try_context_update(self.handle, data)
    }

    /// Finalize the HMAC and write the tag into `out`.
    ///
    /// `out` must be at least 32 bytes long.
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        embassy_crypto_driver::try_context_finalize(self.handle, out)
    }

    /// Tag length in bytes.
    pub const fn output_size() -> usize {
        32
    }
}

/// Streaming HMAC-SHA-384 context backed by the linked crypto driver.
#[derive(Clone)]
pub struct HmacSha384 {
    handle: ContextHandle,
}

impl HmacSha384 {
    /// Create a new HMAC-SHA-384 context with the given key.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
        let handle = embassy_crypto_driver::try_context_init(Algorithm::HmacSha384 { key })?;
        Ok(Self { handle })
    }

    /// Feed more data into the HMAC.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        embassy_crypto_driver::try_context_update(self.handle, data)
    }

    /// Finalize the HMAC and write the tag into `out`.
    ///
    /// `out` must be at least 48 bytes long.
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        embassy_crypto_driver::try_context_finalize(self.handle, out)
    }

    /// Tag length in bytes.
    pub const fn output_size() -> usize {
        48
    }
}

/// Streaming HMAC-SHA-512 context backed by the linked crypto driver.
#[derive(Clone)]
pub struct HmacSha512 {
    handle: ContextHandle,
}

impl HmacSha512 {
    /// Create a new HMAC-SHA-512 context with the given key.
    pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
        let handle = embassy_crypto_driver::try_context_init(Algorithm::HmacSha512 { key })?;
        Ok(Self { handle })
    }

    /// Feed more data into the HMAC.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        embassy_crypto_driver::try_context_update(self.handle, data)
    }

    /// Finalize the HMAC and write the tag into `out`.
    ///
    /// `out` must be at least 64 bytes long.
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        embassy_crypto_driver::try_context_finalize(self.handle, out)
    }

    /// Tag length in bytes.
    pub const fn output_size() -> usize {
        64
    }
}
