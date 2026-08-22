use crate::types::{Algorithm, Capabilities, CryptoError, HashContext};
use core::future::Future;

pub trait BlockingCryptoDriver {
    fn capabilities(&self) -> Capabilities;
    fn blocking_rng_fill(&mut self, _dest: &mut [u8]) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_aes_128_ecb_encrypt(
        &mut self,
        _block: &mut [u8; 16],
        _key: &[u8; 16],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_aes_128_ecb_decrypt(
        &mut self,
        _block: &mut [u8; 16],
        _key: &[u8; 16],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_aes_128_cmac(
        &mut self,
        _key: &[u8; 16],
        _data: &[u8],
        _out: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_aes_ccm_128_encrypt(
        &mut self,
        _key: &[u8; 16],
        _nonce: &[u8],
        _aad: &[u8],
        _plaintext: &[u8],
        _ciphertext: &mut [u8],
        _tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_aes_ccm_128_decrypt(
        &mut self,
        _key: &[u8; 16],
        _nonce: &[u8],
        _aad: &[u8],
        _ciphertext: &[u8],
        _plaintext: &mut [u8],
        _tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_aes_ccm8_128_encrypt(
        &mut self,
        _key: &[u8; 16],
        _nonce: &[u8],
        _aad: &[u8],
        _plaintext: &[u8],
        _ciphertext: &mut [u8],
        _tag: &mut [u8; 8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_aes_ccm8_128_decrypt(
        &mut self,
        _key: &[u8; 16],
        _nonce: &[u8],
        _aad: &[u8],
        _ciphertext: &[u8],
        _plaintext: &mut [u8],
        _tag: &[u8; 8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_p384_keygen(
        &mut self,
        _secret_key: &mut [u8; 48],
        _public_key: &mut [u8; 96],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_p384_ecdh(
        &mut self,
        _secret_key: &[u8; 48],
        _public_key: &[u8; 96],
        _shared_secret: &mut [u8; 48],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_p384_ecdsa_sign(
        &mut self,
        _secret_key: &[u8; 48],
        _digest: &[u8; 48],
        _signature: &mut [u8; 96],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_p384_ecdsa_verify(
        &mut self,
        _public_key: &[u8; 96],
        _digest: &[u8; 48],
        _signature: &[u8; 96],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_sign_pkcs1v15_sha256(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 32],
        _signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_verify_pkcs1v15_sha256(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 32],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_sign_pkcs1v15_sha384(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 48],
        _signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_verify_pkcs1v15_sha384(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 48],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_sign_pkcs1v15_sha512(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 64],
        _signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_verify_pkcs1v15_sha512(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 64],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_sign_pss_sha256(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 32],
        _signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_verify_pss_sha256(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 32],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_sign_pss_sha384(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 48],
        _signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_verify_pss_sha384(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 48],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_sign_pss_sha512(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 64],
        _signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        Err(CryptoError::Unsupported)
    }
    fn blocking_rsa_verify_pss_sha512(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 64],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Initialize a streaming hash context.
    ///
    /// The driver should zero/reset its internal hash state into `ctx`.
    fn blocking_hash_init(
        &mut self,
        _op: Algorithm,
        _ctx: &mut HashContext,
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Update a streaming hash context with more data.
    fn blocking_hash_update(
        &mut self,
        _op: Algorithm,
        _ctx: &mut HashContext,
        _data: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }

    /// Finalize a streaming hash context and write the digest.
    fn blocking_hash_finalize(
        &mut self,
        _op: Algorithm,
        _ctx: &mut HashContext,
        _out: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::Unsupported)
    }
}

/// Asynchronous cryptographic hardware driver.
///
/// # Safety contract for `no_alloc` async
///
/// Implementations must ensure that caller-provided buffers are not
/// accessed by hardware (e.g. DMA) after the future returned by any
/// method has been dropped. The recommended patterns are:
///
/// 1. **Copy in/out:** Copy caller data into driver-owned DMA buffers
///    before the first yield point, and copy results back to caller
///    buffers after the last yield point. The hardware never touches
///    caller memory directly.
///
/// 2. **Single yield:** If the hardware operates directly on caller
///    buffers, the future must return `Ready` immediately after the
///    hardware operation completes, without any additional yield points
///    while the buffer is in use by the hardware.
///
/// Violating this contract can lead to use-after-free or data corruption,
/// especially on multi-core systems where the caller may have set
/// CANCELLED while the worker was inside poll().
pub trait CryptoDriver: BlockingCryptoDriver {
    fn aes_gcm_128_encrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _plaintext: &'a [u8],
        _ciphertext: &'a mut [u8],
        _tag: &'a mut [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn aes_gcm_128_decrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _ciphertext: &'a [u8],
        _plaintext: &'a mut [u8],
        _tag: &'a [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn aes_gcm_256_encrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 32],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _plaintext: &'a [u8],
        _ciphertext: &'a mut [u8],
        _tag: &'a mut [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn aes_gcm_256_decrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 32],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _ciphertext: &'a [u8],
        _plaintext: &'a mut [u8],
        _tag: &'a [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn aes_ccm_128_encrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _plaintext: &'a [u8],
        _ciphertext: &'a mut [u8],
        _tag: &'a mut [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn aes_ccm_128_decrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _ciphertext: &'a [u8],
        _plaintext: &'a mut [u8],
        _tag: &'a [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn aes_ccm8_128_encrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _plaintext: &'a [u8],
        _ciphertext: &'a mut [u8],
        _tag: &'a mut [u8; 8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn aes_ccm8_128_decrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _ciphertext: &'a [u8],
        _plaintext: &'a mut [u8],
        _tag: &'a [u8; 8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn sha_256<'a>(
        &'a mut self,
        _data: &'a [u8],
        _out: &'a mut [u8; 32],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn sha_384<'a>(
        &'a mut self,
        _data: &'a [u8],
        _out: &'a mut [u8; 48],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn p256_keygen<'a>(
        &'a mut self,
        _secret_key: &'a mut [u8; 32],
        _public_key: &'a mut [u8; 64],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn p256_ecdh<'a>(
        &'a mut self,
        _secret_key: &'a [u8; 32],
        _public_key: &'a [u8; 64],
        _shared_secret: &'a mut [u8; 32],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn p256_ecdsa_sign<'a>(
        &'a mut self,
        _secret_key: &'a [u8; 32],
        _digest: &'a [u8; 32],
        _signature: &'a mut [u8; 64],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn p256_ecdsa_verify<'a>(
        &'a mut self,
        _public_key: &'a [u8; 64],
        _digest: &'a [u8; 32],
        _signature: &'a [u8; 64],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn p384_keygen<'a>(
        &'a mut self,
        _secret_key: &'a mut [u8; 48],
        _public_key: &'a mut [u8; 96],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn p384_ecdh<'a>(
        &'a mut self,
        _secret_key: &'a [u8; 48],
        _public_key: &'a [u8; 96],
        _shared_secret: &'a mut [u8; 48],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn p384_ecdsa_sign<'a>(
        &'a mut self,
        _secret_key: &'a [u8; 48],
        _digest: &'a [u8; 48],
        _signature: &'a mut [u8; 96],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn p384_ecdsa_verify<'a>(
        &'a mut self,
        _public_key: &'a [u8; 96],
        _digest: &'a [u8; 48],
        _signature: &'a [u8; 96],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_sign_pkcs1v15_sha256<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 32],
        _signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_verify_pkcs1v15_sha256<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 32],
        _signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_sign_pkcs1v15_sha384<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 48],
        _signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_verify_pkcs1v15_sha384<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 48],
        _signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_sign_pkcs1v15_sha512<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 64],
        _signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_verify_pkcs1v15_sha512<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 64],
        _signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_sign_pss_sha256<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 32],
        _signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_verify_pss_sha256<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 32],
        _signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_sign_pss_sha384<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 48],
        _signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_verify_pss_sha384<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 48],
        _signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_sign_pss_sha512<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 64],
        _signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
    fn rsa_verify_pss_sha512<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 64],
        _signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }

    fn fill_rng_async<'a>(
        &'a mut self,
        _dest: &'a mut [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
        core::future::ready(Err(CryptoError::Unsupported))
    }
}
