/// Errors returned by global crypto operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// No provider registered that supports the requested operation.
    NoProvider,
    /// The selected provider does not support this algorithm.
    UnsupportedAlgorithm,
    /// An output buffer was too small for the result.
    BufferTooSmall,
    /// AEAD decryption failed (tag mismatch).
    DecryptionFailed,
    /// A handle was invalid or stale.
    InvalidHandle,
    /// The provider's key store is full.
    KeyStoreFull,
    /// DH keys are incompatible (different algorithms).
    IncompatibleKeys,
    /// Key import failed (wrong size or format).
    ImportError,
    /// Hardware accelerator reported an error.
    HwError,
    /// An async operation was cancelled.
    Cancelled,
    /// The hardware is busy with another operation.
    Busy,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CryptoError::NoProvider => f.write_str("no crypto provider available"),
            CryptoError::UnsupportedAlgorithm => f.write_str("algorithm not supported by provider"),
            CryptoError::BufferTooSmall => f.write_str("output buffer too small"),
            CryptoError::DecryptionFailed => f.write_str("AEAD decryption failed"),
            CryptoError::InvalidHandle => f.write_str("invalid crypto handle"),
            CryptoError::KeyStoreFull => f.write_str("provider key store full"),
            CryptoError::IncompatibleKeys => f.write_str("incompatible DH keys"),
            CryptoError::ImportError => f.write_str("key import failed"),
            CryptoError::HwError => f.write_str("hardware accelerator error"),
            CryptoError::Cancelled => f.write_str("operation cancelled"),
            CryptoError::Busy => f.write_str("hardware busy"),
        }
    }
}

impl core::error::Error for CryptoError {}
