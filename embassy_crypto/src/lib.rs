#![cfg_attr(not(test), no_std)]

pub mod queue;
pub mod runner;
pub mod server;

pub use queue::ContextHandle as Sha256ContextHandle;
pub use server::CryptoServer;

use embassy_crypto_driver::{
    BlockingCryptoDriver, Capabilities, CryptoDriver, CryptoError, Sha256Context,
};

pub struct MockDriver;

impl BlockingCryptoDriver for MockDriver {
    fn capabilities(&self) -> Capabilities {
        Capabilities::all()
    }

    fn blocking_rng_fill(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
        dest.fill(0xAB);
        Ok(())
    }

    fn blocking_aes_128_ecb_encrypt(
        &mut self,
        block: &mut [u8; 16],
        _key: &[u8; 16],
    ) -> Result<(), CryptoError> {
        block.fill(0x01);
        Ok(())
    }

    fn blocking_aes_128_ecb_decrypt(
        &mut self,
        block: &mut [u8; 16],
        _key: &[u8; 16],
    ) -> Result<(), CryptoError> {
        block.fill(0x02);
        Ok(())
    }

    fn blocking_aes_128_cmac(
        &mut self,
        _key: &[u8; 16],
        _data: &[u8],
        out: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        out.fill(0x03);
        Ok(())
    }

    fn blocking_aes_ccm_128_encrypt(
        &mut self,
        _key: &[u8; 16],
        _nonce: &[u8],
        _aad: &[u8],
        _plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        ciphertext.fill(0x04);
        tag.fill(0x05);
        Ok(())
    }

    fn blocking_aes_ccm_128_decrypt(
        &mut self,
        _key: &[u8; 16],
        _nonce: &[u8],
        _aad: &[u8],
        _ciphertext: &[u8],
        plaintext: &mut [u8],
        _tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        plaintext.fill(0x06);
        Ok(())
    }

    fn blocking_aes_ccm8_128_encrypt(
        &mut self,
        _key: &[u8; 16],
        _nonce: &[u8],
        _aad: &[u8],
        _plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 8],
    ) -> Result<(), CryptoError> {
        ciphertext.fill(0x07);
        tag.fill(0x08);
        Ok(())
    }

    fn blocking_aes_ccm8_128_decrypt(
        &mut self,
        _key: &[u8; 16],
        _nonce: &[u8],
        _aad: &[u8],
        _ciphertext: &[u8],
        plaintext: &mut [u8],
        _tag: &[u8; 8],
    ) -> Result<(), CryptoError> {
        plaintext.fill(0x09);
        Ok(())
    }

    fn blocking_p384_keygen(
        &mut self,
        secret_key: &mut [u8; 48],
        public_key: &mut [u8; 96],
    ) -> Result<(), CryptoError> {
        secret_key.fill(0x10);
        public_key.fill(0x11);
        Ok(())
    }

    fn blocking_p384_ecdh(
        &mut self,
        _secret_key: &[u8; 48],
        _public_key: &[u8; 96],
        shared_secret: &mut [u8; 48],
    ) -> Result<(), CryptoError> {
        shared_secret.fill(0x12);
        Ok(())
    }

    fn blocking_p384_ecdsa_sign(
        &mut self,
        _secret_key: &[u8; 48],
        _digest: &[u8; 48],
        signature: &mut [u8; 96],
    ) -> Result<(), CryptoError> {
        signature.fill(0x13);
        Ok(())
    }

    fn blocking_p384_ecdsa_verify(
        &mut self,
        _public_key: &[u8; 96],
        _digest: &[u8; 48],
        _signature: &[u8; 96],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    fn blocking_rsa_sign_pkcs1v15_sha256(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 32],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x20);
        Ok(signature.len())
    }

    fn blocking_rsa_verify_pkcs1v15_sha256(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 32],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    fn blocking_rsa_sign_pkcs1v15_sha384(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 48],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x21);
        Ok(signature.len())
    }

    fn blocking_rsa_verify_pkcs1v15_sha384(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 48],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    fn blocking_rsa_sign_pkcs1v15_sha512(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 64],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x22);
        Ok(signature.len())
    }

    fn blocking_rsa_verify_pkcs1v15_sha512(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 64],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    fn blocking_rsa_sign_pss_sha256(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 32],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x23);
        Ok(signature.len())
    }

    fn blocking_rsa_verify_pss_sha256(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 32],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    fn blocking_rsa_sign_pss_sha384(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 48],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x24);
        Ok(signature.len())
    }

    fn blocking_rsa_verify_pss_sha384(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 48],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    fn blocking_rsa_sign_pss_sha512(
        &mut self,
        _private_key: &[u8],
        _digest: &[u8; 64],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x25);
        Ok(signature.len())
    }

    fn blocking_rsa_verify_pss_sha512(
        &mut self,
        _public_key: &[u8],
        _digest: &[u8; 64],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    fn blocking_sha256_init(&mut self, ctx: &mut Sha256Context) -> Result<(), CryptoError> {
        ctx.0.fill(0);
        Ok(())
    }
}

impl CryptoDriver for MockDriver {
    async fn aes_gcm_128_encrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    ) -> Result<(), CryptoError> {
        ciphertext.fill(0x30);
        tag.fill(0x31);
        Ok(())
    }

    async fn aes_gcm_128_decrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        _tag: &'a [u8; 16],
    ) -> Result<(), CryptoError> {
        plaintext.fill(0x32);
        Ok(())
    }

    async fn aes_gcm_256_encrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 32],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    ) -> Result<(), CryptoError> {
        ciphertext.fill(0x33);
        tag.fill(0x34);
        Ok(())
    }

    async fn aes_gcm_256_decrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 32],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        _tag: &'a [u8; 16],
    ) -> Result<(), CryptoError> {
        plaintext.fill(0x35);
        Ok(())
    }

    async fn aes_ccm_128_encrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    ) -> Result<(), CryptoError> {
        ciphertext.fill(0x36);
        tag.fill(0x37);
        Ok(())
    }

    async fn aes_ccm_128_decrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        _tag: &'a [u8; 16],
    ) -> Result<(), CryptoError> {
        plaintext.fill(0x38);
        Ok(())
    }

    async fn aes_ccm8_128_encrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 8],
    ) -> Result<(), CryptoError> {
        ciphertext.fill(0x39);
        tag.fill(0x3A);
        Ok(())
    }

    async fn aes_ccm8_128_decrypt<'a>(
        &'a mut self,
        _key: &'a [u8; 16],
        _nonce: &'a [u8],
        _aad: &'a [u8],
        _ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        _tag: &'a [u8; 8],
    ) -> Result<(), CryptoError> {
        plaintext.fill(0x3B);
        Ok(())
    }

    async fn sha_256<'a>(
        &'a mut self,
        _data: &'a [u8],
        out: &'a mut [u8; 32],
    ) -> Result<(), CryptoError> {
        out.fill(0x40);
        Ok(())
    }

    async fn sha_384<'a>(
        &'a mut self,
        _data: &'a [u8],
        out: &'a mut [u8; 48],
    ) -> Result<(), CryptoError> {
        out.fill(0x41);
        Ok(())
    }

    async fn p256_keygen<'a>(
        &'a mut self,
        secret_key: &'a mut [u8; 32],
        public_key: &'a mut [u8; 64],
    ) -> Result<(), CryptoError> {
        secret_key.fill(0x50);
        public_key.fill(0x51);
        Ok(())
    }

    async fn p256_ecdh<'a>(
        &'a mut self,
        _secret_key: &'a [u8; 32],
        _public_key: &'a [u8; 64],
        shared_secret: &'a mut [u8; 32],
    ) -> Result<(), CryptoError> {
        shared_secret.fill(0x52);
        Ok(())
    }

    async fn p256_ecdsa_sign<'a>(
        &'a mut self,
        _secret_key: &'a [u8; 32],
        _digest: &'a [u8; 32],
        signature: &'a mut [u8; 64],
    ) -> Result<(), CryptoError> {
        signature.fill(0x53);
        Ok(())
    }

    async fn p256_ecdsa_verify<'a>(
        &'a mut self,
        _public_key: &'a [u8; 64],
        _digest: &'a [u8; 32],
        _signature: &'a [u8; 64],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn p384_keygen<'a>(
        &'a mut self,
        secret_key: &'a mut [u8; 48],
        public_key: &'a mut [u8; 96],
    ) -> Result<(), CryptoError> {
        secret_key.fill(0x60);
        public_key.fill(0x61);
        Ok(())
    }

    async fn p384_ecdh<'a>(
        &'a mut self,
        _secret_key: &'a [u8; 48],
        _public_key: &'a [u8; 96],
        shared_secret: &'a mut [u8; 48],
    ) -> Result<(), CryptoError> {
        shared_secret.fill(0x62);
        Ok(())
    }

    async fn p384_ecdsa_sign<'a>(
        &'a mut self,
        _secret_key: &'a [u8; 48],
        _digest: &'a [u8; 48],
        signature: &'a mut [u8; 96],
    ) -> Result<(), CryptoError> {
        signature.fill(0x63);
        Ok(())
    }

    async fn p384_ecdsa_verify<'a>(
        &'a mut self,
        _public_key: &'a [u8; 96],
        _digest: &'a [u8; 48],
        _signature: &'a [u8; 96],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn rsa_sign_pkcs1v15_sha256<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 32],
        signature: &'a mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x70);
        Ok(signature.len())
    }

    async fn rsa_verify_pkcs1v15_sha256<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 32],
        _signature: &'a [u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn rsa_sign_pkcs1v15_sha384<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 48],
        signature: &'a mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x71);
        Ok(signature.len())
    }

    async fn rsa_verify_pkcs1v15_sha384<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 48],
        _signature: &'a [u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn rsa_sign_pkcs1v15_sha512<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 64],
        signature: &'a mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x72);
        Ok(signature.len())
    }

    async fn rsa_verify_pkcs1v15_sha512<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 64],
        _signature: &'a [u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn rsa_sign_pss_sha256<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 32],
        signature: &'a mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x73);
        Ok(signature.len())
    }

    async fn rsa_verify_pss_sha256<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 32],
        _signature: &'a [u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn rsa_sign_pss_sha384<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 48],
        signature: &'a mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x74);
        Ok(signature.len())
    }

    async fn rsa_verify_pss_sha384<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 48],
        _signature: &'a [u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn rsa_sign_pss_sha512<'a>(
        &'a mut self,
        _private_key: &'a [u8],
        _digest: &'a [u8; 64],
        signature: &'a mut [u8],
    ) -> Result<usize, CryptoError> {
        signature.fill(0x75);
        Ok(signature.len())
    }

    async fn rsa_verify_pss_sha512<'a>(
        &'a mut self,
        _public_key: &'a [u8],
        _digest: &'a [u8; 64],
        _signature: &'a [u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn sha256_update<'a>(
        &'a mut self,
        _ctx: &'a mut Sha256Context,
        _data: &'a [u8],
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    async fn sha256_finalize<'a>(
        &'a mut self,
        _ctx: &'a mut Sha256Context,
        out: &'a mut [u8; 32],
    ) -> Result<(), CryptoError> {
        out.fill(0x0A);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::mutex::Mutex;

    #[tokio::test]
    async fn test_single_driver() {
        let runner: runner::CryptoRunner<(Mutex<CriticalSectionRawMutex, MockDriver>,), 16> =
            runner::CryptoRunner::new((MockDriver,));
        let server = runner.server();

        let mut buf = [0u8; 32];
        server.blocking_rng_fill(&mut buf).unwrap();
        assert_eq!(buf, [0xAB; 32]);

        let mut out = [0u8; 32];
        server.sha_256(b"hello", &mut out).await.unwrap();
        assert_eq!(out, [0x40; 32]);
    }

    #[tokio::test]
    async fn test_two_drivers() {
        let runner: runner::CryptoRunner<
            (
                Mutex<CriticalSectionRawMutex, MockDriver>,
                Mutex<CriticalSectionRawMutex, MockDriver>,
            ),
            16,
        > = runner::CryptoRunner::new((MockDriver, MockDriver));
        let server = runner.server();

        let mut out = [0u8; 32];
        server.sha_256(b"world", &mut out).await.unwrap();
        assert_eq!(out, [0x40; 32]);
    }

    #[tokio::test]
    async fn test_streaming_sha256() {
        let runner: runner::CryptoRunner<(Mutex<CriticalSectionRawMutex, MockDriver>,), 16> =
            runner::CryptoRunner::new((MockDriver,));
        let server = runner.server();

        let ctx = server.sha256_init().unwrap();
        server.sha256_update(ctx, b"hello").await.unwrap();
        server.sha256_update(ctx, b" world").await.unwrap();
        let mut out = [0u8; 32];
        server.sha256_finalize(ctx, &mut out).await.unwrap();
        assert_eq!(out, [0x0A; 32]);
    }
}
