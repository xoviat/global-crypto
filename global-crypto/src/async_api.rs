//! Async cryptographic API and driver extension trait.
//!
//! Hardware accelerators that support interrupt-driven async operation
//! should implement [`AsyncCryptoDriver`]. The global async functions
//! currently delegate to the synchronous API; true async operation
//! requires a separate async-capable registry (future work).

use crate::types::*;
use crate::CryptoError;

// ============================================================================
// Async driver trait
// ============================================================================

/// Extension trait for async-capable crypto drivers.
///
/// The provider IS the state machine: only one operation can be in flight
/// at a time. This is tracked by an atomic state variable inside the provider.
pub trait AsyncCryptoDriver: crate::driver::CryptoDriver {
    /// Try to atomically acquire the hardware. Returns `false` if busy.
    fn try_acquire(&self) -> bool;

    /// Release the hardware back to idle and wake any waiters.
    fn release(&self);

    /// Register a waker to be called when the hardware becomes idle.
    fn register_idle_waker(&self, waker: &core::task::Waker);

    /// Start an async AEAD encryption operation.
    ///
    /// # Safety
    /// `message` and `tag_out` must remain valid and dereferenceable until
    /// `poll()` returns `Ready` or `cancel()` is called.
    unsafe fn start_aead_encrypt(
        &self,
        alg: crate::AeadAlgorithmId,
        key: &[u8],
        nonce: &[u8],
        message: *mut u8,
        message_len: usize,
        aad: &[u8],
        tag_out: *mut u8,
        tag_len: usize,
    ) -> Result<(), CryptoError>;

    /// Poll the single in-flight operation.
    fn poll(&self, cx: &mut core::task::Context) -> core::task::Poll<Result<(), CryptoError>>;

    /// Cancel the in-flight operation and return to idle.
    fn cancel(&self);
}

// ============================================================================
// Async wrappers (currently thin delegates to sync API)
// ============================================================================

/// Async AEAD encryption.
#[inline]
pub async fn aead_encrypt<A: AeadAlgorithm>(
    key: &AeadKey<A>,
    nonce: &Nonce<A>,
    message: &mut [u8],
    aad: &[u8],
    tag: &mut Tag<A>,
) -> Result<(), CryptoError> {
    crate::sync_api::aead_encrypt::<A>(key, nonce, message, aad, tag)
}

/// Async AEAD decryption.
#[inline]
pub async fn aead_decrypt<A: AeadAlgorithm>(
    key: &AeadKey<A>,
    nonce: &Nonce<A>,
    message: &mut [u8],
    tag: &Tag<A>,
    aad: &[u8],
) -> Result<(), CryptoError> {
    crate::sync_api::aead_decrypt::<A>(key, nonce, message, tag, aad)
}

/// Async hash.
#[inline]
pub async fn hash<A: HashAlgorithm>(data: &[u8]) -> Result<HashOutput<A>, CryptoError> {
    crate::sync_api::hash::<A>(data)
}

/// Async HMAC.
#[inline]
pub async fn hmac<A: HmacAlgorithm>(key: &[u8], data: &[u8]) -> Result<HmacOutput<A>, CryptoError> {
    crate::sync_api::hmac::<A>(key, data)
}

/// Async DH keypair generation.
#[inline]
pub async fn dh_generate_keypair<A: DhAlgorithm>() -> Result<(DhPublicKey<A>, DhSecretKey<A>), CryptoError> {
    crate::sync_api::dh_generate_keypair::<A>()
}

/// Async shared secret derivation.
#[inline]
pub async fn dh_shared_secret<A: DhAlgorithm>(
    seckey: &DhSecretKey<A>,
    pubkey: &DhPublicKey<A>,
) -> Result<DhSharedSecret<A>, CryptoError> {
    crate::sync_api::dh_shared_secret::<A>(seckey, pubkey)
}

/// Async HKDF-Extract.
#[inline]
pub async fn hkdf_extract<A: HmacAlgorithm>(
    salt: Option<&[u8]>,
    ikm: &[u8],
) -> Result<HmacOutput<A>, CryptoError> {
    crate::sync_api::hkdf_extract::<A>(salt, ikm)
}

/// Async HKDF-Expand.
#[inline]
pub async fn hkdf_expand<A: HmacAlgorithm>(
    prk: &HmacOutput<A>,
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    crate::sync_api::hkdf_expand::<A>(prk, info, okm)
}

/// Async CORDIC computation.
#[inline]
pub async fn cordic_compute<A: CordicAlgorithm>(
    input: &CordicInput<A>,
) -> Result<CordicOutput<A>, CryptoError> {
    crate::sync_api::cordic_compute::<A>(input)
}
