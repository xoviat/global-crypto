use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::runner::RunnerBackend;
use embassy_crypto_driver::{Capabilities, CryptoError};

/// Type-erased crypto server.
///
/// Created via `CryptoRunner::server()`. All methods are object-safe and
/// require no heap allocation.
pub struct CryptoServer<'a> {
    pub(crate) backend: &'a dyn RunnerBackend,
}

// ===================================================================
// Blocking fast-path methods
// ===================================================================

impl CryptoServer<'_> {
    pub fn rng_fill(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::RNG, &mut |drv| drv.rng_fill(dest))
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn aes_128_ecb_encrypt(
        &self,
        block: &mut [u8; 16],
        key: &[u8; 16],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::AES_128_ECB, &mut |drv| {
                drv.aes_128_ecb_encrypt(block, key)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn aes_128_ecb_decrypt(
        &self,
        block: &mut [u8; 16],
        key: &[u8; 16],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::AES_128_ECB, &mut |drv| {
                drv.aes_128_ecb_decrypt(block, key)
            })
            .unwrap_or(Err(CryptoError::HardwareError))
    }

    pub fn aes_128_cmac(
        &self,
        key: &[u8; 16],
        data: &[u8],
        out: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        self.backend
            .try_blocking(Capabilities::AES_128_CMAC, &mut |drv| {
                drv.aes_128_cmac(key, data, out)
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
            Some(h) => this.backend.poll_op(h, cx),
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
            Some(h) => this.backend.poll_op(h, cx),
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
            Some(h) => this.backend.poll_op(h, cx),
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
            Some(h) => this.backend.poll_op(h, cx),
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
            Some(h) => this.backend.poll_op(h, cx),
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
            Some(h) => this.backend.poll_op(h, cx),
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
    pub fn sha_256<'a>(
        &'a self,
        data: &'a [u8],
        out: &'a mut [u8; 32],
    ) -> Sha256Future<'a> {
        Sha256Future {
            backend: self.backend,
            data,
            out,
            handle: None,
        }
    }

    pub fn sha_384<'a>(
        &'a self,
        data: &'a [u8],
        out: &'a mut [u8; 48],
    ) -> Sha384Future<'a> {
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
                let handle = this.backend.schedule_p256_keygen(this.secret_key, this.public_key)?;
                this.handle = Some(handle);
                Poll::Pending
            }
            Some(h) => this.backend.poll_op(h, cx),
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
            Some(h) => this.backend.poll_op(h, cx),
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
            Some(h) => this.backend.poll_op(h, cx),
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
            Some(h) => this.backend.poll_op(h, cx),
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
