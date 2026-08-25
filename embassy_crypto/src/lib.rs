#![no_std]

pub use embassy_crypto_driver::{
    Algorithm, BlockingOp, ContextHandle, CryptoError, HashContext,
};

// ------------------------------------------------------------------
// Blocking dispatch (thin wrapper around the driver free function)
// ------------------------------------------------------------------

/// Dispatch a blocking operation to the linked crypto driver.
///
/// Returns `Err(CryptoError::Unsupported)` if the driver does not
/// provide an implementation.
pub fn dispatch_blocking(op: BlockingOp<'_>) -> Result<(), CryptoError> {
    match embassy_crypto_driver::dispatch_blocking(op) {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(e),
        None => Err(CryptoError::Unsupported),
    }
}

// ------------------------------------------------------------------
// Hash
// ------------------------------------------------------------------

/// Streaming hash context backed by the linked crypto driver.
///
/// Create with [`Hash::new`], feed data with [`Hash::update`],
/// and finish with [`Hash::finalize_into`].
pub struct Hash {
    handle: ContextHandle,
    output_size: usize,
}

impl Hash {
    /// Create a new hash context for the given algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidInput`] if `alg` is an HMAC variant.
    pub fn new(alg: Algorithm<'_>) -> Result<Self, CryptoError> {
        if alg.is_hmac() {
            return Err(CryptoError::InvalidInput);
        }
        let handle = embassy_crypto_driver::try_context_init(alg)?;
        Ok(Self {
            handle,
            output_size: alg.digest_len(),
        })
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
    /// `out` must be at least [`Hash::output_size`] bytes long.
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        embassy_crypto_driver::try_context_finalize(self.handle, out)
    }

    /// Digest length in bytes.
    pub const fn output_size(&self) -> usize {
        self.output_size
    }
}

impl Clone for Hash {
    fn clone(&self) -> Self {
        let handle = embassy_crypto_driver::try_context_clone(self.handle)
            .expect("embassy_crypto: failed to clone hash context");
        Self {
            handle,
            output_size: self.output_size,
        }
    }
}

// ------------------------------------------------------------------
// Hmac
// ------------------------------------------------------------------

/// Streaming HMAC context backed by the linked crypto driver.
///
/// Create with [`Hmac::new`], feed data with [`Hmac::update`],
/// and finish with [`Hmac::finalize_into`].
pub struct Hmac {
    handle: ContextHandle,
    output_size: usize,
}

impl Hmac {
    /// Create a new HMAC context.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidInput`] if `alg` is not an HMAC variant.
    pub fn new(alg: Algorithm<'_>) -> Result<Self, CryptoError> {
        if !alg.is_hmac() {
            return Err(CryptoError::InvalidInput);
        }
        let handle = embassy_crypto_driver::try_context_init(alg)?;
        Ok(Self {
            handle,
            output_size: alg.digest_len(),
        })
    }

    /// Feed more data into the HMAC.
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        embassy_crypto_driver::try_context_update(self.handle, data)
    }

    /// Finalize the HMAC and write the tag into `out`.
    ///
    /// `out` must be at least [`Hmac::output_size`] bytes long.
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        embassy_crypto_driver::try_context_finalize(self.handle, out)
    }

    /// Tag length in bytes.
    pub const fn output_size(&self) -> usize {
        self.output_size
    }
}

impl Clone for Hmac {
    fn clone(&self) -> Self {
        let handle = embassy_crypto_driver::try_context_clone(self.handle)
            .expect("embassy_crypto: failed to clone hmac context");
        Self {
            handle,
            output_size: self.output_size,
        }
    }
}
