use core::future::Future;
use crate::types::{Capabilities, CryptoError};

/// Object-safe subset of the driver interface.
///
/// Used for synchronous fast-path operations and for the runner's
/// `try_blocking` dispatch.
pub trait BlockingCryptoDriver {
    fn capabilities(&self) -> Capabilities;

    fn rng_fill(&mut self, dest: &mut [u8]) -> Result<(), CryptoError>;

    fn aes_128_ecb_encrypt(
        &mut self,
        block: &mut [u8; 16],
        key: &[u8; 16],
    ) -> Result<(), CryptoError>;

    fn aes_128_ecb_decrypt(
        &mut self,
        block: &mut [u8; 16],
        key: &[u8; 16],
    ) -> Result<(), CryptoError>;

    fn aes_128_cmac(
        &mut self,
        key: &[u8; 16],
        data: &[u8],
        out: &mut [u8; 16],
    ) -> Result<(), CryptoError>;
}

/// Full driver trait with async operations.
///
/// This trait is **not object-safe** because methods return `impl Future`.
/// It is only used inside the runner's per-driver worker futures, where the
/// compiler can name the anonymous future types on the async stack.
pub trait CryptoDriver: BlockingCryptoDriver {
    // ------------------------------------------------------------------
    // AES-128-GCM
    // ------------------------------------------------------------------
    fn aes_gcm_128_encrypt<'a>(
        &'a mut self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;

    fn aes_gcm_128_decrypt<'a>(
        &'a mut self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;

    // ------------------------------------------------------------------
    // AES-256-GCM
    // ------------------------------------------------------------------
    fn aes_gcm_256_encrypt<'a>(
        &'a mut self,
        key: &'a [u8; 32],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;

    fn aes_gcm_256_decrypt<'a>(
        &'a mut self,
        key: &'a [u8; 32],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;

    // ------------------------------------------------------------------
    // SHA
    // ------------------------------------------------------------------
    fn sha_256<'a>(
        &'a mut self,
        data: &'a [u8],
        out: &'a mut [u8; 32],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;

    fn sha_384<'a>(
        &'a mut self,
        data: &'a [u8],
        out: &'a mut [u8; 48],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;

    // ------------------------------------------------------------------
    // P-256
    // ------------------------------------------------------------------
    fn p256_keygen<'a>(
        &'a mut self,
        secret_key: &'a mut [u8; 32],
        public_key: &'a mut [u8; 64],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;

    fn p256_ecdh<'a>(
        &'a mut self,
        secret_key: &'a [u8; 32],
        public_key: &'a [u8; 64],
        shared_secret: &'a mut [u8; 32],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;

    fn p256_ecdsa_sign<'a>(
        &'a mut self,
        secret_key: &'a [u8; 32],
        digest: &'a [u8; 32],
        signature: &'a mut [u8; 64],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;

    fn p256_ecdsa_verify<'a>(
        &'a mut self,
        public_key: &'a [u8; 64],
        digest: &'a [u8; 32],
        signature: &'a [u8; 64],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
}
