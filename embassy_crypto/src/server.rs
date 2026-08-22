use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::runner::RunnerBackend;
use embassy_crypto_driver::{Capabilities, CryptoError};

pub struct CryptoServer<'a> {
    pub(crate) backend: &'a dyn RunnerBackend,
}

impl CryptoServer<'_> {
    pub fn blocking_rng_fill(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::RNG, &mut |drv| drv.blocking_rng_fill(dest))
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_aes_128_ecb_encrypt(
        &self,
        block: &mut [u8; 16],
        key: &[u8; 16],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::AES_128_ECB, &mut |drv| {
                drv.blocking_aes_128_ecb_encrypt(block, key)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_aes_128_ecb_decrypt(
        &self,
        block: &mut [u8; 16],
        key: &[u8; 16],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::AES_128_ECB, &mut |drv| {
                drv.blocking_aes_128_ecb_decrypt(block, key)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_aes_128_cmac(
        &self,
        key: &[u8; 16],
        data: &[u8],
        out: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::AES_128_CMAC, &mut |drv| {
                drv.blocking_aes_128_cmac(key, data, out)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_aes_ccm_128_encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::AES_128_CCM, &mut |drv| {
                drv.blocking_aes_ccm_128_encrypt(key, nonce, aad, plaintext, ciphertext, tag)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_aes_ccm_128_decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::AES_128_CCM, &mut |drv| {
                drv.blocking_aes_ccm_128_decrypt(key, nonce, aad, ciphertext, plaintext, tag)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_aes_ccm8_128_encrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 8],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::AES_128_CCM8, &mut |drv| {
                drv.blocking_aes_ccm8_128_encrypt(key, nonce, aad, plaintext, ciphertext, tag)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_aes_ccm8_128_decrypt(
        &self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::AES_128_CCM8, &mut |drv| {
                drv.blocking_aes_ccm8_128_decrypt(key, nonce, aad, ciphertext, plaintext, tag)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_p384_keygen(
        &self,
        secret_key: &mut [u8; 48],
        public_key: &mut [u8; 96],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::P384_KEYGEN, &mut |drv| {
                drv.blocking_p384_keygen(secret_key, public_key)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_p384_ecdh(
        &self,
        secret_key: &[u8; 48],
        public_key: &[u8; 96],
        shared_secret: &mut [u8; 48],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::P384_ECDH, &mut |drv| {
                drv.blocking_p384_ecdh(secret_key, public_key, shared_secret)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_p384_ecdsa_sign(
        &self,
        secret_key: &[u8; 48],
        digest: &[u8; 48],
        signature: &mut [u8; 96],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::P384_ECDSA_SIGN, &mut |drv| {
                drv.blocking_p384_ecdsa_sign(secret_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_p384_ecdsa_verify(
        &self,
        public_key: &[u8; 96],
        digest: &[u8; 48],
        signature: &[u8; 96],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::P384_ECDSA_VERIFY, &mut |drv| {
                drv.blocking_p384_ecdsa_verify(public_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_sign_pkcs1v15_sha256(
        &self,
        private_key: &[u8],
        digest: &[u8; 32],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.backend
            .try_blocking_size(Capabilities::RSA_PKCS1V15_SHA256, &mut |drv| {
                drv.blocking_rsa_sign_pkcs1v15_sha256(private_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_verify_pkcs1v15_sha256(
        &self,
        public_key: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::RSA_PKCS1V15_SHA256, &mut |drv| {
                drv.blocking_rsa_verify_pkcs1v15_sha256(public_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_sign_pkcs1v15_sha384(
        &self,
        private_key: &[u8],
        digest: &[u8; 48],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.backend
            .try_blocking_size(Capabilities::RSA_PKCS1V15_SHA384, &mut |drv| {
                drv.blocking_rsa_sign_pkcs1v15_sha384(private_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_verify_pkcs1v15_sha384(
        &self,
        public_key: &[u8],
        digest: &[u8; 48],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::RSA_PKCS1V15_SHA384, &mut |drv| {
                drv.blocking_rsa_verify_pkcs1v15_sha384(public_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_sign_pkcs1v15_sha512(
        &self,
        private_key: &[u8],
        digest: &[u8; 64],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.backend
            .try_blocking_size(Capabilities::RSA_PKCS1V15_SHA512, &mut |drv| {
                drv.blocking_rsa_sign_pkcs1v15_sha512(private_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_verify_pkcs1v15_sha512(
        &self,
        public_key: &[u8],
        digest: &[u8; 64],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::RSA_PKCS1V15_SHA512, &mut |drv| {
                drv.blocking_rsa_verify_pkcs1v15_sha512(public_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_sign_pss_sha256(
        &self,
        private_key: &[u8],
        digest: &[u8; 32],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.backend
            .try_blocking_size(Capabilities::RSA_PSS_SHA256, &mut |drv| {
                drv.blocking_rsa_sign_pss_sha256(private_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_verify_pss_sha256(
        &self,
        public_key: &[u8],
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::RSA_PSS_SHA256, &mut |drv| {
                drv.blocking_rsa_verify_pss_sha256(public_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_sign_pss_sha384(
        &self,
        private_key: &[u8],
        digest: &[u8; 48],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.backend
            .try_blocking_size(Capabilities::RSA_PSS_SHA384, &mut |drv| {
                drv.blocking_rsa_sign_pss_sha384(private_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_verify_pss_sha384(
        &self,
        public_key: &[u8],
        digest: &[u8; 48],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::RSA_PSS_SHA384, &mut |drv| {
                drv.blocking_rsa_verify_pss_sha384(public_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_sign_pss_sha512(
        &self,
        private_key: &[u8],
        digest: &[u8; 64],
        signature: &mut [u8],
    ) -> Result<usize, CryptoError> {
        self.backend
            .try_blocking_size(Capabilities::RSA_PSS_SHA512, &mut |drv| {
                drv.blocking_rsa_sign_pss_sha512(private_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn blocking_rsa_verify_pss_sha512(
        &self,
        public_key: &[u8],
        digest: &[u8; 64],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::RSA_PSS_SHA512, &mut |drv| {
                drv.blocking_rsa_verify_pss_sha512(public_key, digest, signature)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }
}

// ===================================================================
// AES-128-GCM
// ===================================================================

pub struct AesGcm128EncryptFuture<'a> {
    backend: &'a dyn RunnerBackend,
    key: &'a [u8; 16],
    nonce: &'a [u8],
    aad: &'a [u8],
    plaintext: &'a [u8],
    ciphertext: &'a mut [u8],
    tag: &'a mut [u8; 16],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for AesGcm128EncryptFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_aes_gcm_128_encrypt(
                    this.key,
                    this.nonce,
                    this.aad,
                    this.plaintext,
                    this.ciphertext,
                    this.tag,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for AesGcm128EncryptFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct AesGcm128DecryptFuture<'a> {
    backend: &'a dyn RunnerBackend,
    key: &'a [u8; 16],
    nonce: &'a [u8],
    aad: &'a [u8],
    ciphertext: &'a [u8],
    plaintext: &'a mut [u8],
    tag: &'a [u8; 16],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for AesGcm128DecryptFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_aes_gcm_128_decrypt(
                    this.key,
                    this.nonce,
                    this.aad,
                    this.ciphertext,
                    this.plaintext,
                    this.tag,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for AesGcm128DecryptFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn aes_gcm_128_encrypt<'a>(
        &'a self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    ) -> AesGcm128EncryptFuture<'a> {
        AesGcm128EncryptFuture {
            backend: self.backend,
            key,
            nonce,
            aad,
            plaintext,
            ciphertext,
            tag,
            handle: None,
        }
    }
    pub fn aes_gcm_128_decrypt<'a>(
        &'a self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    ) -> AesGcm128DecryptFuture<'a> {
        AesGcm128DecryptFuture {
            backend: self.backend,
            key,
            nonce,
            aad,
            ciphertext,
            plaintext,
            tag,
            handle: None,
        }
    }
}

// ===================================================================
// AES-256-GCM
// ===================================================================

pub struct AesGcm256EncryptFuture<'a> {
    backend: &'a dyn RunnerBackend,
    key: &'a [u8; 32],
    nonce: &'a [u8],
    aad: &'a [u8],
    plaintext: &'a [u8],
    ciphertext: &'a mut [u8],
    tag: &'a mut [u8; 16],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for AesGcm256EncryptFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_aes_gcm_256_encrypt(
                    this.key,
                    this.nonce,
                    this.aad,
                    this.plaintext,
                    this.ciphertext,
                    this.tag,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for AesGcm256EncryptFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct AesGcm256DecryptFuture<'a> {
    backend: &'a dyn RunnerBackend,
    key: &'a [u8; 32],
    nonce: &'a [u8],
    aad: &'a [u8],
    ciphertext: &'a [u8],
    plaintext: &'a mut [u8],
    tag: &'a [u8; 16],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for AesGcm256DecryptFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_aes_gcm_256_decrypt(
                    this.key,
                    this.nonce,
                    this.aad,
                    this.ciphertext,
                    this.plaintext,
                    this.tag,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for AesGcm256DecryptFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn aes_gcm_256_encrypt<'a>(
        &'a self,
        key: &'a [u8; 32],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    ) -> AesGcm256EncryptFuture<'a> {
        AesGcm256EncryptFuture {
            backend: self.backend,
            key,
            nonce,
            aad,
            plaintext,
            ciphertext,
            tag,
            handle: None,
        }
    }
    pub fn aes_gcm_256_decrypt<'a>(
        &'a self,
        key: &'a [u8; 32],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    ) -> AesGcm256DecryptFuture<'a> {
        AesGcm256DecryptFuture {
            backend: self.backend,
            key,
            nonce,
            aad,
            ciphertext,
            plaintext,
            tag,
            handle: None,
        }
    }
}

// ===================================================================
// AES-128-CCM
// ===================================================================

pub struct AesCcm128EncryptFuture<'a> {
    backend: &'a dyn RunnerBackend,
    key: &'a [u8; 16],
    nonce: &'a [u8],
    aad: &'a [u8],
    plaintext: &'a [u8],
    ciphertext: &'a mut [u8],
    tag: &'a mut [u8; 16],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for AesCcm128EncryptFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_aes_ccm_128_encrypt(
                    this.key,
                    this.nonce,
                    this.aad,
                    this.plaintext,
                    this.ciphertext,
                    this.tag,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for AesCcm128EncryptFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct AesCcm128DecryptFuture<'a> {
    backend: &'a dyn RunnerBackend,
    key: &'a [u8; 16],
    nonce: &'a [u8],
    aad: &'a [u8],
    ciphertext: &'a [u8],
    plaintext: &'a mut [u8],
    tag: &'a [u8; 16],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for AesCcm128DecryptFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_aes_ccm_128_decrypt(
                    this.key,
                    this.nonce,
                    this.aad,
                    this.ciphertext,
                    this.plaintext,
                    this.tag,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for AesCcm128DecryptFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn aes_ccm_128_encrypt<'a>(
        &'a self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    ) -> AesCcm128EncryptFuture<'a> {
        AesCcm128EncryptFuture {
            backend: self.backend,
            key,
            nonce,
            aad,
            plaintext,
            ciphertext,
            tag,
            handle: None,
        }
    }
    pub fn aes_ccm_128_decrypt<'a>(
        &'a self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    ) -> AesCcm128DecryptFuture<'a> {
        AesCcm128DecryptFuture {
            backend: self.backend,
            key,
            nonce,
            aad,
            ciphertext,
            plaintext,
            tag,
            handle: None,
        }
    }
}

// ===================================================================
// AES-128-CCM8
// ===================================================================

pub struct AesCcm8_128EncryptFuture<'a> {
    backend: &'a dyn RunnerBackend,
    key: &'a [u8; 16],
    nonce: &'a [u8],
    aad: &'a [u8],
    plaintext: &'a [u8],
    ciphertext: &'a mut [u8],
    tag: &'a mut [u8; 8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for AesCcm8_128EncryptFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_aes_ccm8_128_encrypt(
                    this.key,
                    this.nonce,
                    this.aad,
                    this.plaintext,
                    this.ciphertext,
                    this.tag,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for AesCcm8_128EncryptFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct AesCcm8_128DecryptFuture<'a> {
    backend: &'a dyn RunnerBackend,
    key: &'a [u8; 16],
    nonce: &'a [u8],
    aad: &'a [u8],
    ciphertext: &'a [u8],
    plaintext: &'a mut [u8],
    tag: &'a [u8; 8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for AesCcm8_128DecryptFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_aes_ccm8_128_decrypt(
                    this.key,
                    this.nonce,
                    this.aad,
                    this.ciphertext,
                    this.plaintext,
                    this.tag,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for AesCcm8_128DecryptFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn aes_ccm8_128_encrypt<'a>(
        &'a self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 8],
    ) -> AesCcm8_128EncryptFuture<'a> {
        AesCcm8_128EncryptFuture {
            backend: self.backend,
            key,
            nonce,
            aad,
            plaintext,
            ciphertext,
            tag,
            handle: None,
        }
    }
    pub fn aes_ccm8_128_decrypt<'a>(
        &'a self,
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 8],
    ) -> AesCcm8_128DecryptFuture<'a> {
        AesCcm8_128DecryptFuture {
            backend: self.backend,
            key,
            nonce,
            aad,
            ciphertext,
            plaintext,
            tag,
            handle: None,
        }
    }
}

// ===================================================================
// SHA
// ===================================================================

pub struct Sha256Future<'a> {
    backend: &'a dyn RunnerBackend,
    data: &'a [u8],
    out: &'a mut [u8; 32],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for Sha256Future<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_sha_256(this.data, this.out)?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for Sha256Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct Sha384Future<'a> {
    backend: &'a dyn RunnerBackend,
    data: &'a [u8],
    out: &'a mut [u8; 48],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for Sha384Future<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_sha_384(this.data, this.out)?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for Sha384Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn sha_256<'a>(&'a self, data: &'a [u8], out: &'a mut [u8; 32]) -> Sha256Future<'a> {
        Sha256Future {
            backend: self.backend,
            data,
            out,
            handle: None,
        }
    }
    pub fn sha_384<'a>(&'a self, data: &'a [u8], out: &'a mut [u8; 48]) -> Sha384Future<'a> {
        Sha384Future {
            backend: self.backend,
            data,
            out,
            handle: None,
        }
    }
}

// ===================================================================
// P-256
// ===================================================================

pub struct P256KeygenFuture<'a> {
    backend: &'a dyn RunnerBackend,
    secret_key: &'a mut [u8; 32],
    public_key: &'a mut [u8; 64],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for P256KeygenFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this
                    .backend
                    .schedule_p256_keygen(this.secret_key, this.public_key)?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for P256KeygenFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct P256EcdhFuture<'a> {
    backend: &'a dyn RunnerBackend,
    secret_key: &'a [u8; 32],
    public_key: &'a [u8; 64],
    shared_secret: &'a mut [u8; 32],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for P256EcdhFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_p256_ecdh(
                    this.secret_key,
                    this.public_key,
                    this.shared_secret,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for P256EcdhFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct P256EcdsaSignFuture<'a> {
    backend: &'a dyn RunnerBackend,
    secret_key: &'a [u8; 32],
    digest: &'a [u8; 32],
    signature: &'a mut [u8; 64],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for P256EcdsaSignFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_p256_ecdsa_sign(
                    this.secret_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for P256EcdsaSignFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct P256EcdsaVerifyFuture<'a> {
    backend: &'a dyn RunnerBackend,
    public_key: &'a [u8; 64],
    digest: &'a [u8; 32],
    signature: &'a [u8; 64],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for P256EcdsaVerifyFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_p256_ecdsa_verify(
                    this.public_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for P256EcdsaVerifyFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn p256_keygen<'a>(
        &'a self,
        secret_key: &'a mut [u8; 32],
        public_key: &'a mut [u8; 64],
    ) -> P256KeygenFuture<'a> {
        P256KeygenFuture {
            backend: self.backend,
            secret_key,
            public_key,
            handle: None,
        }
    }
    pub fn p256_ecdh<'a>(
        &'a self,
        secret_key: &'a [u8; 32],
        public_key: &'a [u8; 64],
        shared_secret: &'a mut [u8; 32],
    ) -> P256EcdhFuture<'a> {
        P256EcdhFuture {
            backend: self.backend,
            secret_key,
            public_key,
            shared_secret,
            handle: None,
        }
    }
    pub fn p256_ecdsa_sign<'a>(
        &'a self,
        secret_key: &'a [u8; 32],
        digest: &'a [u8; 32],
        signature: &'a mut [u8; 64],
    ) -> P256EcdsaSignFuture<'a> {
        P256EcdsaSignFuture {
            backend: self.backend,
            secret_key,
            digest,
            signature,
            handle: None,
        }
    }
    pub fn p256_ecdsa_verify<'a>(
        &'a self,
        public_key: &'a [u8; 64],
        digest: &'a [u8; 32],
        signature: &'a [u8; 64],
    ) -> P256EcdsaVerifyFuture<'a> {
        P256EcdsaVerifyFuture {
            backend: self.backend,
            public_key,
            digest,
            signature,
            handle: None,
        }
    }
}

// ===================================================================
// P-384
// ===================================================================

pub struct P384KeygenFuture<'a> {
    backend: &'a dyn RunnerBackend,
    secret_key: &'a mut [u8; 48],
    public_key: &'a mut [u8; 96],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for P384KeygenFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this
                    .backend
                    .schedule_p384_keygen(this.secret_key, this.public_key)?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for P384KeygenFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct P384EcdhFuture<'a> {
    backend: &'a dyn RunnerBackend,
    secret_key: &'a [u8; 48],
    public_key: &'a [u8; 96],
    shared_secret: &'a mut [u8; 48],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for P384EcdhFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_p384_ecdh(
                    this.secret_key,
                    this.public_key,
                    this.shared_secret,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for P384EcdhFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct P384EcdsaSignFuture<'a> {
    backend: &'a dyn RunnerBackend,
    secret_key: &'a [u8; 48],
    digest: &'a [u8; 48],
    signature: &'a mut [u8; 96],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for P384EcdsaSignFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_p384_ecdsa_sign(
                    this.secret_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for P384EcdsaSignFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct P384EcdsaVerifyFuture<'a> {
    backend: &'a dyn RunnerBackend,
    public_key: &'a [u8; 96],
    digest: &'a [u8; 48],
    signature: &'a [u8; 96],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for P384EcdsaVerifyFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_p384_ecdsa_verify(
                    this.public_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for P384EcdsaVerifyFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn p384_keygen<'a>(
        &'a self,
        secret_key: &'a mut [u8; 48],
        public_key: &'a mut [u8; 96],
    ) -> P384KeygenFuture<'a> {
        P384KeygenFuture {
            backend: self.backend,
            secret_key,
            public_key,
            handle: None,
        }
    }
    pub fn p384_ecdh<'a>(
        &'a self,
        secret_key: &'a [u8; 48],
        public_key: &'a [u8; 96],
        shared_secret: &'a mut [u8; 48],
    ) -> P384EcdhFuture<'a> {
        P384EcdhFuture {
            backend: self.backend,
            secret_key,
            public_key,
            shared_secret,
            handle: None,
        }
    }
    pub fn p384_ecdsa_sign<'a>(
        &'a self,
        secret_key: &'a [u8; 48],
        digest: &'a [u8; 48],
        signature: &'a mut [u8; 96],
    ) -> P384EcdsaSignFuture<'a> {
        P384EcdsaSignFuture {
            backend: self.backend,
            secret_key,
            digest,
            signature,
            handle: None,
        }
    }
    pub fn p384_ecdsa_verify<'a>(
        &'a self,
        public_key: &'a [u8; 96],
        digest: &'a [u8; 48],
        signature: &'a [u8; 96],
    ) -> P384EcdsaVerifyFuture<'a> {
        P384EcdsaVerifyFuture {
            backend: self.backend,
            public_key,
            digest,
            signature,
            handle: None,
        }
    }
}

// ===================================================================
// RSA PKCS#1 v1.5 + SHA-256
// ===================================================================

pub struct RsaSignPkcs1v15Sha256Future<'a> {
    backend: &'a dyn RunnerBackend,
    private_key: &'a [u8],
    digest: &'a [u8; 32],
    signature: &'a mut [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaSignPkcs1v15Sha256Future<'_> {
    type Output = Result<usize, CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_sign_pkcs1v15_sha256(
                    this.private_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_size()),
        }
    }
}

impl Drop for RsaSignPkcs1v15Sha256Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct RsaVerifyPkcs1v15Sha256Future<'a> {
    backend: &'a dyn RunnerBackend,
    public_key: &'a [u8],
    digest: &'a [u8; 32],
    signature: &'a [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaVerifyPkcs1v15Sha256Future<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_verify_pkcs1v15_sha256(
                    this.public_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for RsaVerifyPkcs1v15Sha256Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn rsa_sign_pkcs1v15_sha256<'a>(
        &'a self,
        private_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a mut [u8],
    ) -> RsaSignPkcs1v15Sha256Future<'a> {
        RsaSignPkcs1v15Sha256Future {
            backend: self.backend,
            private_key,
            digest,
            signature,
            handle: None,
        }
    }
    pub fn rsa_verify_pkcs1v15_sha256<'a>(
        &'a self,
        public_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a [u8],
    ) -> RsaVerifyPkcs1v15Sha256Future<'a> {
        RsaVerifyPkcs1v15Sha256Future {
            backend: self.backend,
            public_key,
            digest,
            signature,
            handle: None,
        }
    }
}

// ===================================================================
// RSA PKCS#1 v1.5 + SHA-384
// ===================================================================

pub struct RsaSignPkcs1v15Sha384Future<'a> {
    backend: &'a dyn RunnerBackend,
    private_key: &'a [u8],
    digest: &'a [u8; 48],
    signature: &'a mut [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaSignPkcs1v15Sha384Future<'_> {
    type Output = Result<usize, CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_sign_pkcs1v15_sha384(
                    this.private_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_size()),
        }
    }
}

impl Drop for RsaSignPkcs1v15Sha384Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct RsaVerifyPkcs1v15Sha384Future<'a> {
    backend: &'a dyn RunnerBackend,
    public_key: &'a [u8],
    digest: &'a [u8; 48],
    signature: &'a [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaVerifyPkcs1v15Sha384Future<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_verify_pkcs1v15_sha384(
                    this.public_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for RsaVerifyPkcs1v15Sha384Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn rsa_sign_pkcs1v15_sha384<'a>(
        &'a self,
        private_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a mut [u8],
    ) -> RsaSignPkcs1v15Sha384Future<'a> {
        RsaSignPkcs1v15Sha384Future {
            backend: self.backend,
            private_key,
            digest,
            signature,
            handle: None,
        }
    }
    pub fn rsa_verify_pkcs1v15_sha384<'a>(
        &'a self,
        public_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a [u8],
    ) -> RsaVerifyPkcs1v15Sha384Future<'a> {
        RsaVerifyPkcs1v15Sha384Future {
            backend: self.backend,
            public_key,
            digest,
            signature,
            handle: None,
        }
    }
}

// ===================================================================
// RSA PKCS#1 v1.5 + SHA-512
// ===================================================================

pub struct RsaSignPkcs1v15Sha512Future<'a> {
    backend: &'a dyn RunnerBackend,
    private_key: &'a [u8],
    digest: &'a [u8; 64],
    signature: &'a mut [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaSignPkcs1v15Sha512Future<'_> {
    type Output = Result<usize, CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_sign_pkcs1v15_sha512(
                    this.private_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_size()),
        }
    }
}

impl Drop for RsaSignPkcs1v15Sha512Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct RsaVerifyPkcs1v15Sha512Future<'a> {
    backend: &'a dyn RunnerBackend,
    public_key: &'a [u8],
    digest: &'a [u8; 64],
    signature: &'a [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaVerifyPkcs1v15Sha512Future<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_verify_pkcs1v15_sha512(
                    this.public_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for RsaVerifyPkcs1v15Sha512Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn rsa_sign_pkcs1v15_sha512<'a>(
        &'a self,
        private_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a mut [u8],
    ) -> RsaSignPkcs1v15Sha512Future<'a> {
        RsaSignPkcs1v15Sha512Future {
            backend: self.backend,
            private_key,
            digest,
            signature,
            handle: None,
        }
    }
    pub fn rsa_verify_pkcs1v15_sha512<'a>(
        &'a self,
        public_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a [u8],
    ) -> RsaVerifyPkcs1v15Sha512Future<'a> {
        RsaVerifyPkcs1v15Sha512Future {
            backend: self.backend,
            public_key,
            digest,
            signature,
            handle: None,
        }
    }
}

// ===================================================================
// RSA-PSS + SHA-256
// ===================================================================

pub struct RsaSignPssSha256Future<'a> {
    backend: &'a dyn RunnerBackend,
    private_key: &'a [u8],
    digest: &'a [u8; 32],
    signature: &'a mut [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaSignPssSha256Future<'_> {
    type Output = Result<usize, CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_sign_pss_sha256(
                    this.private_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_size()),
        }
    }
}

impl Drop for RsaSignPssSha256Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct RsaVerifyPssSha256Future<'a> {
    backend: &'a dyn RunnerBackend,
    public_key: &'a [u8],
    digest: &'a [u8; 32],
    signature: &'a [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaVerifyPssSha256Future<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_verify_pss_sha256(
                    this.public_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for RsaVerifyPssSha256Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn rsa_sign_pss_sha256<'a>(
        &'a self,
        private_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a mut [u8],
    ) -> RsaSignPssSha256Future<'a> {
        RsaSignPssSha256Future {
            backend: self.backend,
            private_key,
            digest,
            signature,
            handle: None,
        }
    }
    pub fn rsa_verify_pss_sha256<'a>(
        &'a self,
        public_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a [u8],
    ) -> RsaVerifyPssSha256Future<'a> {
        RsaVerifyPssSha256Future {
            backend: self.backend,
            public_key,
            digest,
            signature,
            handle: None,
        }
    }
}

// ===================================================================
// RSA-PSS + SHA-384
// ===================================================================

pub struct RsaSignPssSha384Future<'a> {
    backend: &'a dyn RunnerBackend,
    private_key: &'a [u8],
    digest: &'a [u8; 48],
    signature: &'a mut [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaSignPssSha384Future<'_> {
    type Output = Result<usize, CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_sign_pss_sha384(
                    this.private_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_size()),
        }
    }
}

impl Drop for RsaSignPssSha384Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct RsaVerifyPssSha384Future<'a> {
    backend: &'a dyn RunnerBackend,
    public_key: &'a [u8],
    digest: &'a [u8; 48],
    signature: &'a [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaVerifyPssSha384Future<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_verify_pss_sha384(
                    this.public_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for RsaVerifyPssSha384Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn rsa_sign_pss_sha384<'a>(
        &'a self,
        private_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a mut [u8],
    ) -> RsaSignPssSha384Future<'a> {
        RsaSignPssSha384Future {
            backend: self.backend,
            private_key,
            digest,
            signature,
            handle: None,
        }
    }
    pub fn rsa_verify_pss_sha384<'a>(
        &'a self,
        public_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a [u8],
    ) -> RsaVerifyPssSha384Future<'a> {
        RsaVerifyPssSha384Future {
            backend: self.backend,
            public_key,
            digest,
            signature,
            handle: None,
        }
    }
}

// ===================================================================
// RSA-PSS + SHA-512
// ===================================================================

pub struct RsaSignPssSha512Future<'a> {
    backend: &'a dyn RunnerBackend,
    private_key: &'a [u8],
    digest: &'a [u8; 64],
    signature: &'a mut [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaSignPssSha512Future<'_> {
    type Output = Result<usize, CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_sign_pss_sha512(
                    this.private_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_size()),
        }
    }
}

impl Drop for RsaSignPssSha512Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct RsaVerifyPssSha512Future<'a> {
    backend: &'a dyn RunnerBackend,
    public_key: &'a [u8],
    digest: &'a [u8; 64],
    signature: &'a [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for RsaVerifyPssSha512Future<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_rsa_verify_pss_sha512(
                    this.public_key,
                    this.digest,
                    this.signature,
                )?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for RsaVerifyPssSha512Future<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

impl CryptoServer<'_> {
    pub fn rsa_sign_pss_sha512<'a>(
        &'a self,
        private_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a mut [u8],
    ) -> RsaSignPssSha512Future<'a> {
        RsaSignPssSha512Future {
            backend: self.backend,
            private_key,
            digest,
            signature,
            handle: None,
        }
    }
    pub fn rsa_verify_pss_sha512<'a>(
        &'a self,
        public_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a [u8],
    ) -> RsaVerifyPssSha512Future<'a> {
        RsaVerifyPssSha512Future {
            backend: self.backend,
            public_key,
            digest,
            signature,
            handle: None,
        }
    }
}

// ===================================================================
// SHA-256 Streaming
// ===================================================================

impl CryptoServer<'_> {
    pub fn sha256_init(&self) -> Result<crate::queue::ContextHandle, CryptoError> {
        self.backend.try_sha256_init()
    }

    pub fn sha256_update<'a>(
        &'a self,
        ctx: crate::queue::ContextHandle,
        data: &'a [u8],
    ) -> Sha256UpdateFuture<'a> {
        Sha256UpdateFuture {
            backend: self.backend,
            ctx,
            data,
            handle: None,
        }
    }

    pub fn sha256_finalize<'a>(
        &'a self,
        ctx: crate::queue::ContextHandle,
        out: &'a mut [u8; 32],
    ) -> Sha256FinalizeFuture<'a> {
        Sha256FinalizeFuture {
            backend: self.backend,
            ctx,
            out,
            handle: None,
        }
    }
}

pub struct Sha256UpdateFuture<'a> {
    backend: &'a dyn RunnerBackend,
    ctx: crate::queue::ContextHandle,
    data: &'a [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for Sha256UpdateFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_sha256_update(this.ctx, this.data)?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for Sha256UpdateFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}

pub struct Sha256FinalizeFuture<'a> {
    backend: &'a dyn RunnerBackend,
    ctx: crate::queue::ContextHandle,
    out: &'a mut [u8; 32],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for Sha256FinalizeFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule_sha256_finalize(this.ctx, this.out)?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
        }
    }
}

impl Drop for Sha256FinalizeFuture<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle {
            let _ = self.backend.cancel_op(h);
        }
    }
}
