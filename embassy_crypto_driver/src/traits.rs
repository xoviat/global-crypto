use crate::types::{Capabilities, CryptoError};
use core::future::Future;

pub trait BlockingCryptoDriver {
    fn capabilities(&self) -> Capabilities;
    fn blocking_rng_fill(&mut self, dest: &mut [u8]) -> Result<(), CryptoError>;
    fn blocking_aes_128_ecb_encrypt(
        &mut self,
        block: &mut [u8; 16],
        key: &[u8; 16],
    ) -> Result<(), CryptoError>;
    fn blocking_aes_128_ecb_decrypt(
        &mut self,
        block: &mut [u8; 16],
        key: &[u8; 16],
    ) -> Result<(), CryptoError>;
    fn blocking_aes_128_cmac(
        &mut self,
        key: &[u8; 16],
        data: &[u8],
        out: &mut [u8; 16],
    ) -> Result<(), CryptoError>;
    fn blocking_aes_ccm_128_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError>;
    fn blocking_aes_ccm_128_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError>;
    fn blocking_aes_ccm8_128_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 8],
    ) -> Result<(), CryptoError>;
    fn blocking_aes_ccm8_128_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), CryptoError>;
    fn blocking_p384_keygen(
        &mut self,
        secret_key: &mut [u8; 48],
        public_key: &mut [u8; 96],
    ) -> Result<(), CryptoError>;
    fn blocking_p384_ecdh(
        &mut self,
        secret_key: &[u8; 48],
        public_key: &[u8; 96],
        shared_secret: &mut [u8; 48],
    ) -> Result<(), CryptoError>;
    fn blocking_p384_ecdsa_sign(
        &mut self,
        secret_key: &[u8; 48],
        digest: &[u8; 48],
        signature: &mut [u8; 96],
    ) -> Result<(), CryptoError>;
    fn blocking_p384_ecdsa_verify(
        &mut self,
        public_key: &[u8; 96],
        digest: &[u8; 48],
        signature: &[u8; 96],
    ) -> Result<(), CryptoError>;
    fn blocking_rsa_sign_pkcs1v15_sha256(
        &mut self,
        private_key: &[u8],
        digest: &[u8; 32],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError>;
    fn blocking_rsa_verify_pkcs1v15_sha256(
        &mut self,
        public_key: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
    fn blocking_rsa_sign_pkcs1v15_sha384(
        &mut self,
        private_key: &[u8],
        digest: &[u8; 48],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError>;
    fn blocking_rsa_verify_pkcs1v15_sha384(
        &mut self,
        public_key: &[u8],
        digest: &[u8; 48],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
    fn blocking_rsa_sign_pkcs1v15_sha512(
        &mut self,
        private_key: &[u8],
        digest: &[u8; 64],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError>;
    fn blocking_rsa_verify_pkcs1v15_sha512(
        &mut self,
        public_key: &[u8],
        digest: &[u8; 64],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
    fn blocking_rsa_sign_pss_sha256(
        &mut self,
        private_key: &[u8],
        digest: &[u8; 32],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError>;
    fn blocking_rsa_verify_pss_sha256(
        &mut self,
        public_key: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
    fn blocking_rsa_sign_pss_sha384(
        &mut self,
        private_key: &[u8],
        digest: &[u8; 48],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError>;
    fn blocking_rsa_verify_pss_sha384(
        &mut self,
        public_key: &[u8],
        digest: &[u8; 48],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
    fn blocking_rsa_sign_pss_sha512(
        &mut self,
        private_key: &[u8],
        digest: &[u8; 64],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError>;
    fn blocking_rsa_verify_pss_sha512(
        &mut self,
        public_key: &[u8],
        digest: &[u8; 64],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
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
    fn aes_ccm_128_encrypt<'a>(
        &'a mut self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn aes_ccm_128_decrypt<'a>(
        &'a mut self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn aes_ccm8_128_encrypt<'a>(
        &'a mut self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn aes_ccm8_128_decrypt<'a>(
        &'a mut self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
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
    fn p384_keygen<'a>(
        &'a mut self,
        secret_key: &'a mut [u8; 48],
        public_key: &'a mut [u8; 96],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn p384_ecdh<'a>(
        &'a mut self,
        secret_key: &'a [u8; 48],
        public_key: &'a [u8; 96],
        shared_secret: &'a mut [u8; 48],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn p384_ecdsa_sign<'a>(
        &'a mut self,
        secret_key: &'a [u8; 48],
        digest: &'a [u8; 48],
        signature: &'a mut [u8; 96],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn p384_ecdsa_verify<'a>(
        &'a mut self,
        public_key: &'a [u8; 96],
        digest: &'a [u8; 48],
        signature: &'a [u8; 96],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn rsa_sign_pkcs1v15_sha256<'a>(
        &'a mut self,
        private_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a;
    fn rsa_verify_pkcs1v15_sha256<'a>(
        &'a mut self,
        public_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn rsa_sign_pkcs1v15_sha384<'a>(
        &'a mut self,
        private_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a;
    fn rsa_verify_pkcs1v15_sha384<'a>(
        &'a mut self,
        public_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn rsa_sign_pkcs1v15_sha512<'a>(
        &'a mut self,
        private_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a;
    fn rsa_verify_pkcs1v15_sha512<'a>(
        &'a mut self,
        public_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn rsa_sign_pss_sha256<'a>(
        &'a mut self,
        private_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a;
    fn rsa_verify_pss_sha256<'a>(
        &'a mut self,
        public_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn rsa_sign_pss_sha384<'a>(
        &'a mut self,
        private_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a;
    fn rsa_verify_pss_sha384<'a>(
        &'a mut self,
        public_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
    fn rsa_sign_pss_sha512<'a>(
        &'a mut self,
        private_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a mut [u8],
    ) -> impl Future<Output = Result<usize, CryptoError>> + 'a;
    fn rsa_verify_pss_sha512<'a>(
        &'a mut self,
        public_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a [u8],
    ) -> impl Future<Output = Result<(), CryptoError>> + 'a;
}
