#![no_std]
#![doc = "Global cryptography backend unitrait and types."]

use core::fmt;

// ------------------------------------------------------------------
// Error type
// ------------------------------------------------------------------

/// Error type for crypto operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    Unsupported,
    InvalidKey,
    InvalidInput,
    InvalidSignature,
    BufferTooSmall,
    HardwareError,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "unsupported operation"),
            Self::InvalidKey => write!(f, "invalid key"),
            Self::InvalidInput => write!(f, "invalid input"),
            Self::InvalidSignature => write!(f, "invalid signature / tag"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::HardwareError => write!(f, "hardware error"),
        }
    }
}

// ------------------------------------------------------------------
// Algorithm
// ------------------------------------------------------------------

/// Hash or HMAC algorithm selection for streaming operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm<'a> {
    SHA1,
    MD5,
    SHA224,
    SHA256,
    SHA384,
    SHA512_224,
    SHA512_256,
    SHA512,
    HmacSha256 { key: &'a [u8] },
    HmacSha384 { key: &'a [u8] },
    HmacSha512 { key: &'a [u8] },
}

impl Algorithm<'_> {
    /// Output digest length in bytes.
    pub const fn digest_len(&self) -> usize {
        match self {
            Self::SHA1 => 20,
            Self::MD5 => 16,
            Self::SHA224 => 28,
            Self::SHA256 => 32,
            Self::SHA384 => 48,
            Self::SHA512_224 => 28,
            Self::SHA512_256 => 32,
            Self::SHA512 => 64,
            Self::HmacSha256 { .. } => 32,
            Self::HmacSha384 { .. } => 48,
            Self::HmacSha512 { .. } => 64,
        }
    }

    /// Returns `true` if this is an HMAC variant.
    pub const fn is_hmac(&self) -> bool {
        match self {
            Self::HmacSha256 { .. } | Self::HmacSha384 { .. } | Self::HmacSha512 { .. } => true,
            _ => false,
        }
    }
}

// ------------------------------------------------------------------
// HashContext
// ------------------------------------------------------------------

/// Opaque context buffer for streaming hash operations.
#[derive(Clone, Copy)]
pub struct HashContext(pub [u8; 256]);

impl Default for HashContext {
    fn default() -> Self {
        Self([0u8; 256])
    }
}

// ------------------------------------------------------------------
// ContextHandle
// ------------------------------------------------------------------

/// Opaque handle to a streaming hash or HMAC context.
#[derive(Clone, Copy)]
pub struct ContextHandle(pub usize);

// ------------------------------------------------------------------
// BlockingOp
// ------------------------------------------------------------------

/// Discriminated union of all blocking symmetric crypto operations.
pub enum BlockingOp<'a> {
    Aes128EcbEncrypt {
        block: &'a mut [u8; 16],
        key: &'a [u8; 16],
    },
    Aes128EcbDecrypt {
        block: &'a mut [u8; 16],
        key: &'a [u8; 16],
    },
    Aes128Cmac {
        key: &'a [u8; 16],
        data: &'a [u8],
        out: &'a mut [u8; 16],
    },
    AesCcm128Encrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    },
    AesCcm128Decrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    },
    AesCcm8_128Encrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 8],
    },
    AesCcm8_128Decrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 8],
    },
    AesGcm128Encrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    },
    AesGcm128Decrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    },
    AesGcm256Encrypt {
        key: &'a [u8; 32],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    },
    AesGcm256Decrypt {
        key: &'a [u8; 32],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    },
    RngFill {
        dest: &'a mut [u8],
    },
}

// ------------------------------------------------------------------
// Unitrait
// ------------------------------------------------------------------

unitrait::unitrait! {
    /// Global cryptography backend.
    ///
    /// Implemented by exactly one crate in the dependency tree.
    /// Provides blocking symmetric cipher, hash, and RNG operations.
    pub trait CryptoDriver {
        /// Dispatch a blocking symmetric operation.
        #[symbol = "_embassy_crypto_dispatch_blocking"]
        pub fn dispatch_blocking(op: BlockingOp<'_>) -> Option<Result<(), CryptoError>>;

        /// Initialize a streaming hash or HMAC context.
        #[symbol = "_embassy_crypto_try_context_init"]
        pub fn try_context_init(op: Algorithm<'_>) -> Result<ContextHandle, CryptoError>;

        /// Update a streaming hash or HMAC context with more data.
        #[symbol = "_embassy_crypto_try_context_update"]
        pub fn try_context_update(handle: ContextHandle, data: &[u8]) -> Result<(), CryptoError>;

        /// Reset a streaming hash or HMAC context to its initial state.
        #[symbol = "_embassy_crypto_try_context_reset"]
        pub fn try_context_reset(handle: ContextHandle) -> Result<(), CryptoError>;

        /// Clone an existing streaming hash or HMAC context.
        #[symbol = "_embassy_crypto_try_context_clone"]
        pub fn try_context_clone(handle: ContextHandle) -> Result<ContextHandle, CryptoError>;

        /// Finalize a streaming hash or HMAC context and write the digest.
        #[symbol = "_embassy_crypto_try_context_finalize"]
        pub fn try_context_finalize(handle: ContextHandle, out: &mut [u8]) -> Result<(), CryptoError>;

        /// Fill random bytes from the global RNG.
        #[symbol = "_embassy_crypto_try_rng_fill"]
        pub fn try_rng_fill(dest: &mut [u8]) -> Option<Result<(), CryptoError>>;
    }

    macro crypto_driver_impl(path = $crate);
}
