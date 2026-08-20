#![no_std]
#![feature(impl_trait_in_assoc_type)]

pub mod queue;
pub mod runner;
pub mod server;

pub use embassy_crypto_driver::{BlockingCryptoDriver, Capabilities, CryptoDriver, CryptoError};
pub use runner::CryptoRunner;
pub use server::CryptoServer;

#[cfg(test)]
mod tests {
    use super::*;
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::mutex::Mutex;

    /// A mock driver that claims to support every capability.
    struct MockDriver;

    impl BlockingCryptoDriver for MockDriver {
        fn capabilities(&self) -> Capabilities {
            Capabilities::all()
        }

        fn rng_fill(&mut self, dest: &mut [u8]) -> Result<(), CryptoError> {
            dest.fill(0x42);
            Ok(())
        }

        fn aes_128_ecb_encrypt(
            &mut self,
            block: &mut [u8; 16],
            _key: &[u8; 16],
        ) -> Result<(), CryptoError> {
            block.fill(0x01);
            Ok(())
        }

        fn aes_128_ecb_decrypt(
            &mut self,
            block: &mut [u8; 16],
            _key: &[u8; 16],
        ) -> Result<(), CryptoError> {
            block.fill(0x02);
            Ok(())
        }

        fn aes_128_cmac(
            &mut self,
            _key: &[u8; 16],
            _data: &[u8],
            out: &mut [u8; 16],
        ) -> Result<(), CryptoError> {
            out.fill(0x03);
            Ok(())
        }

        fn aes_ccm_128_encrypt(
            &mut self,
            _key: &[u8; 16],
            _nonce: &[u8],
            _aad: &[u8],
            _plaintext: &[u8],
            ciphertext: &mut [u8],
            tag: &mut [u8; 16],
        ) -> Result<(), CryptoError> {
            ciphertext.fill(0x10);
            tag.fill(0x11);
            Ok(())
        }

        fn aes_ccm_128_decrypt(
            &mut self,
            _key: &[u8; 16],
            _nonce: &[u8],
            _aad: &[u8],
            _ciphertext: &[u8],
            plaintext: &mut [u8],
            _tag: &[u8; 16],
        ) -> Result<(), CryptoError> {
            plaintext.fill(0x12);
            Ok(())
        }

        fn aes_ccm8_128_encrypt(
            &mut self,
            _key: &[u8; 16],
            _nonce: &[u8],
            _aad: &[u8],
            _plaintext: &[u8],
            ciphertext: &mut [u8],
            tag: &mut [u8; 8],
        ) -> Result<(), CryptoError> {
            ciphertext.fill(0x13);
            tag.fill(0x14);
            Ok(())
        }

        fn aes_ccm8_128_decrypt(
            &mut self,
            _key: &[u8; 16],
            _nonce: &[u8],
            _aad: &[u8],
            _ciphertext: &[u8],
            plaintext: &mut [u8],
            _tag: &[u8; 8],
        ) -> Result<(), CryptoError> {
            plaintext.fill(0x15);
            Ok(())
        }

        fn p384_keygen(
            &mut self,
            secret_key: &mut [u8; 48],
            public_key: &mut [u8; 96],
        ) -> Result<(), CryptoError> {
            secret_key.fill(0x30);
            public_key.fill(0x31);
            Ok(())
        }

        fn p384_ecdh(
            &mut self,
            _secret_key: &[u8; 48],
            _public_key: &[u8; 96],
            shared_secret: &mut [u8; 48],
        ) -> Result<(), CryptoError> {
            shared_secret.fill(0x32);
            Ok(())
        }

        fn p384_ecdsa_sign(
            &mut self,
            _secret_key: &[u8; 48],
            _digest: &[u8; 48],
            signature: &mut [u8; 96],
        ) -> Result<(), CryptoError> {
            signature.fill(0x33);
            Ok(())
        }

        fn p384_ecdsa_verify(
            &mut self,
            _public_key: &[u8; 96],
            _digest: &[u8; 48],
            _signature: &[u8; 96],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        fn rsa_sign_pkcs1v15_sha256(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 32],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x40);
            Ok(signature.len())
        }

        fn rsa_verify_pkcs1v15_sha256(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 32],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        fn rsa_sign_pkcs1v15_sha384(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 48],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x41);
            Ok(signature.len())
        }

        fn rsa_verify_pkcs1v15_sha384(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 48],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        fn rsa_sign_pkcs1v15_sha512(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 64],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x42);
            Ok(signature.len())
        }

        fn rsa_verify_pkcs1v15_sha512(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 64],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        fn rsa_sign_pss_sha256(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 32],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x50);
            Ok(signature.len())
        }

        fn rsa_verify_pss_sha256(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 32],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        fn rsa_sign_pss_sha384(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 48],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x51);
            Ok(signature.len())
        }

        fn rsa_verify_pss_sha384(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 48],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        fn rsa_sign_pss_sha512(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 64],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x52);
            Ok(signature.len())
        }

        fn rsa_verify_pss_sha512(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 64],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }
    }

    impl CryptoDriver for MockDriver {
        async fn aes_gcm_128_encrypt(
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

        async fn aes_gcm_128_decrypt(
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

        async fn aes_gcm_256_encrypt(
            &mut self,
            _key: &[u8; 32],
            _nonce: &[u8],
            _aad: &[u8],
            _plaintext: &[u8],
            ciphertext: &mut [u8],
            tag: &mut [u8; 16],
        ) -> Result<(), CryptoError> {
            ciphertext.fill(0x07);
            tag.fill(0x08);
            Ok(())
        }

        async fn aes_gcm_256_decrypt(
            &mut self,
            _key: &[u8; 32],
            _nonce: &[u8],
            _aad: &[u8],
            _ciphertext: &[u8],
            plaintext: &mut [u8],
            _tag: &[u8; 16],
        ) -> Result<(), CryptoError> {
            plaintext.fill(0x09);
            Ok(())
        }

        async fn aes_ccm_128_encrypt(
            &mut self,
            _key: &[u8; 16],
            _nonce: &[u8],
            _aad: &[u8],
            _plaintext: &[u8],
            ciphertext: &mut [u8],
            tag: &mut [u8; 16],
        ) -> Result<(), CryptoError> {
            ciphertext.fill(0x10);
            tag.fill(0x11);
            Ok(())
        }

        async fn aes_ccm_128_decrypt(
            &mut self,
            _key: &[u8; 16],
            _nonce: &[u8],
            _aad: &[u8],
            _ciphertext: &[u8],
            plaintext: &mut [u8],
            _tag: &[u8; 16],
        ) -> Result<(), CryptoError> {
            plaintext.fill(0x12);
            Ok(())
        }

        async fn aes_ccm8_128_encrypt(
            &mut self,
            _key: &[u8; 16],
            _nonce: &[u8],
            _aad: &[u8],
            _plaintext: &[u8],
            ciphertext: &mut [u8],
            tag: &mut [u8; 8],
        ) -> Result<(), CryptoError> {
            ciphertext.fill(0x13);
            tag.fill(0x14);
            Ok(())
        }

        async fn aes_ccm8_128_decrypt(
            &mut self,
            _key: &[u8; 16],
            _nonce: &[u8],
            _aad: &[u8],
            _ciphertext: &[u8],
            plaintext: &mut [u8],
            _tag: &[u8; 8],
        ) -> Result<(), CryptoError> {
            plaintext.fill(0x15);
            Ok(())
        }

        async fn sha_256(&mut self, _data: &[u8], out: &mut [u8; 32]) -> Result<(), CryptoError> {
            out.fill(0x0A);
            Ok(())
        }

        async fn sha_384(&mut self, _data: &[u8], out: &mut [u8; 48]) -> Result<(), CryptoError> {
            out.fill(0x0B);
            Ok(())
        }

        async fn p256_keygen(
            &mut self,
            secret_key: &mut [u8; 32],
            public_key: &mut [u8; 64],
        ) -> Result<(), CryptoError> {
            secret_key.fill(0x0C);
            public_key.fill(0x0D);
            Ok(())
        }

        async fn p256_ecdh(
            &mut self,
            _secret_key: &[u8; 32],
            _public_key: &[u8; 64],
            shared_secret: &mut [u8; 32],
        ) -> Result<(), CryptoError> {
            shared_secret.fill(0x0E);
            Ok(())
        }

        async fn p256_ecdsa_sign(
            &mut self,
            _secret_key: &[u8; 32],
            _digest: &[u8; 32],
            signature: &mut [u8; 64],
        ) -> Result<(), CryptoError> {
            signature.fill(0x0F);
            Ok(())
        }

        async fn p256_ecdsa_verify(
            &mut self,
            _public_key: &[u8; 64],
            _digest: &[u8; 32],
            _signature: &[u8; 64],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        async fn p384_keygen(
            &mut self,
            secret_key: &mut [u8; 48],
            public_key: &mut [u8; 96],
        ) -> Result<(), CryptoError> {
            secret_key.fill(0x30);
            public_key.fill(0x31);
            Ok(())
        }

        async fn p384_ecdh(
            &mut self,
            _secret_key: &[u8; 48],
            _public_key: &[u8; 96],
            shared_secret: &mut [u8; 48],
        ) -> Result<(), CryptoError> {
            shared_secret.fill(0x32);
            Ok(())
        }

        async fn p384_ecdsa_sign(
            &mut self,
            _secret_key: &[u8; 48],
            _digest: &[u8; 48],
            signature: &mut [u8; 96],
        ) -> Result<(), CryptoError> {
            signature.fill(0x33);
            Ok(())
        }

        async fn p384_ecdsa_verify(
            &mut self,
            _public_key: &[u8; 96],
            _digest: &[u8; 48],
            _signature: &[u8; 96],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        async fn rsa_sign_pkcs1v15_sha256(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 32],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x40);
            Ok(signature.len())
        }

        async fn rsa_verify_pkcs1v15_sha256(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 32],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        async fn rsa_sign_pkcs1v15_sha384(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 48],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x41);
            Ok(signature.len())
        }

        async fn rsa_verify_pkcs1v15_sha384(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 48],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        async fn rsa_sign_pkcs1v15_sha512(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 64],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x42);
            Ok(signature.len())
        }

        async fn rsa_verify_pkcs1v15_sha512(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 64],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        async fn rsa_sign_pss_sha256(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 32],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x50);
            Ok(signature.len())
        }

        async fn rsa_verify_pss_sha256(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 32],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        async fn rsa_sign_pss_sha384(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 48],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x51);
            Ok(signature.len())
        }

        async fn rsa_verify_pss_sha384(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 48],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }

        async fn rsa_sign_pss_sha512(
            &mut self,
            _private_key: &[u8],
            _digest: &[u8; 64],
            signature: &mut [u8],
        ) -> Result<usize, CryptoError> {
            signature.fill(0x52);
            Ok(signature.len())
        }

        async fn rsa_verify_pss_sha512(
            &mut self,
            _public_key: &[u8],
            _digest: &[u8; 64],
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            Ok(())
        }
    }

    #[test]
    fn test_capabilities() {
        let driver = MockDriver;
        let caps = driver.capabilities();
        assert!(caps.contains(Capabilities::AES_128_GCM));
        assert!(caps.contains(Capabilities::AES_256_GCM));
        assert!(caps.contains(Capabilities::SHA_256));
        assert!(caps.contains(Capabilities::P256_KEYGEN));
        assert!(caps.contains(Capabilities::P384_KEYGEN));
        assert!(caps.contains(Capabilities::RSA_PKCS1V15_SHA256));
        assert!(caps.contains(Capabilities::RSA_PSS_SHA512));
    }

    #[test]
    fn test_blocking_fast_path() {
        let driver = MockDriver;
        let mut block = [0u8; 16];
        driver.aes_128_ecb_encrypt(&mut block, &[0u8; 16]).unwrap();
        assert_eq!(block, [0x01; 16]);
    }

    #[test]
    fn test_async_via_runner() {
        // This test just verifies compilation; full async tests would need an executor.
        let _driver = MockDriver;
        // let runner = CryptoRunner::new((&Mutex::new(driver),));
        // let _server = runner.server();
    }
}
