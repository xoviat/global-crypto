use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::runner::RunnerBackend;
use embassy_crypto_driver::{Capabilities, CryptoError};

/// Generate a blocking crypto operation that returns `Result<(), CryptoError>`.
macro_rules! impl_blocking_op {
    ($name:ident, $cap:expr, $driver_method:ident, [ $($arg:ident: $ty:ty),* $(,)? ]) => {
        pub fn $name(&self, $($arg: $ty),*) -> Result<(), CryptoError> {
            self.backend
                .try_blocking($cap, &mut |drv| drv.$driver_method($($arg),*))
                .unwrap_or(Err(CryptoError::HardwareError))
        }
    };
}

/// Generate a blocking crypto operation that returns `Result<usize, CryptoError>`.
macro_rules! impl_blocking_size_op {
    ($name:ident, $cap:expr, $driver_method:ident, [ $($arg:ident: $ty:ty),* $(,)? ]) => {
        pub fn $name(&self, $($arg: $ty),*) -> Result<usize, CryptoError> {
            self.backend
                .try_blocking_size($cap, &mut |drv| drv.$driver_method($($arg),*))
                .unwrap_or(Err(CryptoError::HardwareError))
        }
    };
}

/// Generate an async future type, its `Future` impl, and its `Drop` impl.
/// `$output` is either `into_unit` or `into_size`.
macro_rules! impl_async_op {
    ($future:ident, $variant:ident, [ $($field:ident: $ty:ty),* $(,)? ]) => {
        pub struct $future<'a> {
            backend: &'a dyn RunnerBackend,
            $($field: $ty),*,
            handle: Option<crate::queue::OpHandle>,
        }

        impl Future for $future<'_> {
            type Output = Result<(), CryptoError>;
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = &mut *self;
                match this.handle {
                    None => {
                        let handle = this.backend.schedule(crate::queue::OpKind::$variant { $($field: this.$field),* })?;
                        this.handle = Some(handle);
                        Poll::Pending
                    }
                    Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_unit()),
                }
            }
        }

        impl Drop for $future<'_> {
            fn drop(&mut self) {
                if let Some(h) = self.handle {
                    let _ = self.backend.cancel_op(h);
                }
            }
        }
    };
}

/// Generate an async future type with `usize` output.
macro_rules! impl_async_size_op {
    ($future:ident, $variant:ident, [ $($field:ident: $ty:ty),* $(,)? ]) => {
        pub struct $future<'a> {
            backend: &'a dyn RunnerBackend,
            $($field: $ty),*,
            handle: Option<crate::queue::OpHandle>,
        }

        impl Future for $future<'_> {
            type Output = Result<usize, CryptoError>;
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = &mut *self;
                match this.handle {
                    None => {
                        let handle = this.backend.schedule(crate::queue::OpKind::$variant { $($field: this.$field),* })?;
                        this.handle = Some(handle);
                        Poll::Pending
                    }
                    Some(h) => this.backend.poll_op(h, cx).map(|o| o.into_size()),
                }
            }
        }

        impl Drop for $future<'_> {
            fn drop(&mut self) {
                if let Some(h) = self.handle {
                    let _ = self.backend.cancel_op(h);
                }
            }
        }
    };
}

/// Generate a constructor method on `CryptoServer` for an async future.
macro_rules! async_op_ctor {
    ($method:ident, $future:ident, [ $($field:ident: $ty:ty),* $(,)? ]) => {
        pub fn $method<'a>(&'a self, $($field: $ty),*) -> $future<'a> {
            $future { backend: self.backend, $($field),*, handle: None }
        }
    };
}

pub struct CryptoServer<'a> {
    pub(crate) backend: &'a dyn RunnerBackend,
}

impl CryptoServer<'_> {
    // ------------------------------------------------------------------
    // Blocking operations
    // ------------------------------------------------------------------
    impl_blocking_op!(blocking_rng_fill, Capabilities::RNG, blocking_rng_fill, [dest: &mut [u8]]);
    impl_blocking_op!(blocking_aes_128_ecb_encrypt, Capabilities::AES_128_ECB, blocking_aes_128_ecb_encrypt, [block: &mut [u8; 16], key: &[u8; 16]]);
    impl_blocking_op!(blocking_aes_128_ecb_decrypt, Capabilities::AES_128_ECB, blocking_aes_128_ecb_decrypt, [block: &mut [u8; 16], key: &[u8; 16]]);
    impl_blocking_op!(blocking_aes_128_cmac, Capabilities::AES_128_CMAC, blocking_aes_128_cmac, [key: &[u8; 16], data: &[u8], out: &mut [u8; 16]]);
    impl_blocking_op!(blocking_aes_ccm_128_encrypt, Capabilities::AES_128_CCM, blocking_aes_ccm_128_encrypt, [key: &[u8; 16], nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8; 16]]);
    impl_blocking_op!(blocking_aes_ccm_128_decrypt, Capabilities::AES_128_CCM, blocking_aes_ccm_128_decrypt, [key: &[u8; 16], nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8; 16]]);
    impl_blocking_op!(blocking_aes_ccm8_128_encrypt, Capabilities::AES_128_CCM8, blocking_aes_ccm8_128_encrypt, [key: &[u8; 16], nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8; 8]]);
    impl_blocking_op!(blocking_aes_ccm8_128_decrypt, Capabilities::AES_128_CCM8, blocking_aes_ccm8_128_decrypt, [key: &[u8; 16], nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8; 8]]);
    impl_blocking_op!(blocking_p384_keygen, Capabilities::P384_KEYGEN, blocking_p384_keygen, [secret_key: &mut [u8; 48], public_key: &mut [u8; 96]]);
    impl_blocking_op!(blocking_p384_ecdh, Capabilities::P384_ECDH, blocking_p384_ecdh, [secret_key: &[u8; 48], public_key: &[u8; 96], shared_secret: &mut [u8; 48]]);
    impl_blocking_op!(blocking_p384_ecdsa_sign, Capabilities::P384_ECDSA_SIGN, blocking_p384_ecdsa_sign, [secret_key: &[u8; 48], digest: &[u8; 48], signature: &mut [u8; 96]]);
    impl_blocking_op!(blocking_p384_ecdsa_verify, Capabilities::P384_ECDSA_VERIFY, blocking_p384_ecdsa_verify, [public_key: &[u8; 96], digest: &[u8; 48], signature: &[u8; 96]]);

    impl_blocking_size_op!(blocking_rsa_sign_pkcs1v15_sha256, Capabilities::RSA_PKCS1V15_SHA256, blocking_rsa_sign_pkcs1v15_sha256, [private_key: &[u8], digest: &[u8; 32], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pkcs1v15_sha256, Capabilities::RSA_PKCS1V15_SHA256, blocking_rsa_verify_pkcs1v15_sha256, [public_key: &[u8], digest: &[u8; 32], signature: &[u8]]);
    impl_blocking_size_op!(blocking_rsa_sign_pkcs1v15_sha384, Capabilities::RSA_PKCS1V15_SHA384, blocking_rsa_sign_pkcs1v15_sha384, [private_key: &[u8], digest: &[u8; 48], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pkcs1v15_sha384, Capabilities::RSA_PKCS1V15_SHA384, blocking_rsa_verify_pkcs1v15_sha384, [public_key: &[u8], digest: &[u8; 48], signature: &[u8]]);
    impl_blocking_size_op!(blocking_rsa_sign_pkcs1v15_sha512, Capabilities::RSA_PKCS1V15_SHA512, blocking_rsa_sign_pkcs1v15_sha512, [private_key: &[u8], digest: &[u8; 64], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pkcs1v15_sha512, Capabilities::RSA_PKCS1V15_SHA512, blocking_rsa_verify_pkcs1v15_sha512, [public_key: &[u8], digest: &[u8; 64], signature: &[u8]]);
    impl_blocking_size_op!(blocking_rsa_sign_pss_sha256, Capabilities::RSA_PSS_SHA256, blocking_rsa_sign_pss_sha256, [private_key: &[u8], digest: &[u8; 32], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pss_sha256, Capabilities::RSA_PSS_SHA256, blocking_rsa_verify_pss_sha256, [public_key: &[u8], digest: &[u8; 32], signature: &[u8]]);
    impl_blocking_size_op!(blocking_rsa_sign_pss_sha384, Capabilities::RSA_PSS_SHA384, blocking_rsa_sign_pss_sha384, [private_key: &[u8], digest: &[u8; 48], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pss_sha384, Capabilities::RSA_PSS_SHA384, blocking_rsa_verify_pss_sha384, [public_key: &[u8], digest: &[u8; 48], signature: &[u8]]);
    impl_blocking_size_op!(blocking_rsa_sign_pss_sha512, Capabilities::RSA_PSS_SHA512, blocking_rsa_sign_pss_sha512, [private_key: &[u8], digest: &[u8; 64], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pss_sha512, Capabilities::RSA_PSS_SHA512, blocking_rsa_verify_pss_sha512, [public_key: &[u8], digest: &[u8; 64], signature: &[u8]]);

    // ------------------------------------------------------------------
    // Async constructors
    // ------------------------------------------------------------------
    async_op_ctor!(aes_gcm_128_encrypt, AesGcm128EncryptFuture, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], plaintext: &'a [u8], ciphertext: &'a mut [u8], tag: &'a mut [u8; 16]]);
    async_op_ctor!(aes_gcm_128_decrypt, AesGcm128DecryptFuture, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], ciphertext: &'a [u8], plaintext: &'a mut [u8], tag: &'a [u8; 16]]);
    async_op_ctor!(aes_gcm_256_encrypt, AesGcm256EncryptFuture, [key: &'a [u8; 32], nonce: &'a [u8], aad: &'a [u8], plaintext: &'a [u8], ciphertext: &'a mut [u8], tag: &'a mut [u8; 16]]);
    async_op_ctor!(aes_gcm_256_decrypt, AesGcm256DecryptFuture, [key: &'a [u8; 32], nonce: &'a [u8], aad: &'a [u8], ciphertext: &'a [u8], plaintext: &'a mut [u8], tag: &'a [u8; 16]]);
    async_op_ctor!(aes_ccm_128_encrypt, AesCcm128EncryptFuture, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], plaintext: &'a [u8], ciphertext: &'a mut [u8], tag: &'a mut [u8; 16]]);
    async_op_ctor!(aes_ccm_128_decrypt, AesCcm128DecryptFuture, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], ciphertext: &'a [u8], plaintext: &'a mut [u8], tag: &'a [u8; 16]]);
    async_op_ctor!(aes_ccm8_128_encrypt, AesCcm8_128EncryptFuture, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], plaintext: &'a [u8], ciphertext: &'a mut [u8], tag: &'a mut [u8; 8]]);
    async_op_ctor!(aes_ccm8_128_decrypt, AesCcm8_128DecryptFuture, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], ciphertext: &'a [u8], plaintext: &'a mut [u8], tag: &'a [u8; 8]]);
    async_op_ctor!(sha_256, Sha256Future, [data: &'a [u8], out: &'a mut [u8; 32]]);
    async_op_ctor!(sha_384, Sha384Future, [data: &'a [u8], out: &'a mut [u8; 48]]);
    async_op_ctor!(p256_keygen, P256KeygenFuture, [secret_key: &'a mut [u8; 32], public_key: &'a mut [u8; 64]]);
    async_op_ctor!(p256_ecdh, P256EcdhFuture, [secret_key: &'a [u8; 32], public_key: &'a [u8; 64], shared_secret: &'a mut [u8; 32]]);
    async_op_ctor!(p256_ecdsa_sign, P256EcdsaSignFuture, [secret_key: &'a [u8; 32], digest: &'a [u8; 32], signature: &'a mut [u8; 64]]);
    async_op_ctor!(p256_ecdsa_verify, P256EcdsaVerifyFuture, [public_key: &'a [u8; 64], digest: &'a [u8; 32], signature: &'a [u8; 64]]);
    async_op_ctor!(p384_keygen, P384KeygenFuture, [secret_key: &'a mut [u8; 48], public_key: &'a mut [u8; 96]]);
    async_op_ctor!(p384_ecdh, P384EcdhFuture, [secret_key: &'a [u8; 48], public_key: &'a [u8; 96], shared_secret: &'a mut [u8; 48]]);
    async_op_ctor!(p384_ecdsa_sign, P384EcdsaSignFuture, [secret_key: &'a [u8; 48], digest: &'a [u8; 48], signature: &'a mut [u8; 96]]);
    async_op_ctor!(p384_ecdsa_verify, P384EcdsaVerifyFuture, [public_key: &'a [u8; 96], digest: &'a [u8; 48], signature: &'a [u8; 96]]);
    async_op_ctor!(rsa_sign_pkcs1v15_sha256, RsaSignPkcs1v15Sha256Future, [private_key: &'a [u8], digest: &'a [u8; 32], signature: &'a mut [u8]]);
    async_op_ctor!(rsa_verify_pkcs1v15_sha256, RsaVerifyPkcs1v15Sha256Future, [public_key: &'a [u8], digest: &'a [u8; 32], signature: &'a [u8]]);
    async_op_ctor!(rsa_sign_pkcs1v15_sha384, RsaSignPkcs1v15Sha384Future, [private_key: &'a [u8], digest: &'a [u8; 48], signature: &'a mut [u8]]);
    async_op_ctor!(rsa_verify_pkcs1v15_sha384, RsaVerifyPkcs1v15Sha384Future, [public_key: &'a [u8], digest: &'a [u8; 48], signature: &'a [u8]]);
    async_op_ctor!(rsa_sign_pkcs1v15_sha512, RsaSignPkcs1v15Sha512Future, [private_key: &'a [u8], digest: &'a [u8; 64], signature: &'a mut [u8]]);
    async_op_ctor!(rsa_verify_pkcs1v15_sha512, RsaVerifyPkcs1v15Sha512Future, [public_key: &'a [u8], digest: &'a [u8; 64], signature: &'a [u8]]);
    async_op_ctor!(rsa_sign_pss_sha256, RsaSignPssSha256Future, [private_key: &'a [u8], digest: &'a [u8; 32], signature: &'a mut [u8]]);
    async_op_ctor!(rsa_verify_pss_sha256, RsaVerifyPssSha256Future, [public_key: &'a [u8], digest: &'a [u8; 32], signature: &'a [u8]]);
    async_op_ctor!(rsa_sign_pss_sha384, RsaSignPssSha384Future, [private_key: &'a [u8], digest: &'a [u8; 48], signature: &'a mut [u8]]);
    async_op_ctor!(rsa_verify_pss_sha384, RsaVerifyPssSha384Future, [public_key: &'a [u8], digest: &'a [u8; 48], signature: &'a [u8]]);
    async_op_ctor!(rsa_sign_pss_sha512, RsaSignPssSha512Future, [private_key: &'a [u8], digest: &'a [u8; 64], signature: &'a mut [u8]]);
    async_op_ctor!(rsa_verify_pss_sha512, RsaVerifyPssSha512Future, [public_key: &'a [u8], digest: &'a [u8; 64], signature: &'a [u8]]);

    // ------------------------------------------------------------------
    // Streaming SHA-256
    // ------------------------------------------------------------------
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
            ctx_handle: ctx,
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
            ctx_handle: ctx,
            out,
            handle: None,
        }
    }
}

// ------------------------------------------------------------------
// Async future types (unit output)
// ------------------------------------------------------------------
impl_async_op!(AesGcm128EncryptFuture, AesGcm128Encrypt, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], plaintext: &'a [u8], ciphertext: &'a mut [u8], tag: &'a mut [u8; 16]]);
impl_async_op!(AesGcm128DecryptFuture, AesGcm128Decrypt, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], ciphertext: &'a [u8], plaintext: &'a mut [u8], tag: &'a [u8; 16]]);
impl_async_op!(AesGcm256EncryptFuture, AesGcm256Encrypt, [key: &'a [u8; 32], nonce: &'a [u8], aad: &'a [u8], plaintext: &'a [u8], ciphertext: &'a mut [u8], tag: &'a mut [u8; 16]]);
impl_async_op!(AesGcm256DecryptFuture, AesGcm256Decrypt, [key: &'a [u8; 32], nonce: &'a [u8], aad: &'a [u8], ciphertext: &'a [u8], plaintext: &'a mut [u8], tag: &'a [u8; 16]]);
impl_async_op!(AesCcm128EncryptFuture, AesCcm128Encrypt, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], plaintext: &'a [u8], ciphertext: &'a mut [u8], tag: &'a mut [u8; 16]]);
impl_async_op!(AesCcm128DecryptFuture, AesCcm128Decrypt, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], ciphertext: &'a [u8], plaintext: &'a mut [u8], tag: &'a [u8; 16]]);
impl_async_op!(AesCcm8_128EncryptFuture, AesCcm8_128Encrypt, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], plaintext: &'a [u8], ciphertext: &'a mut [u8], tag: &'a mut [u8; 8]]);
impl_async_op!(AesCcm8_128DecryptFuture, AesCcm8_128Decrypt, [key: &'a [u8; 16], nonce: &'a [u8], aad: &'a [u8], ciphertext: &'a [u8], plaintext: &'a mut [u8], tag: &'a [u8; 8]]);
impl_async_op!(Sha256Future, Sha256, [data: &'a [u8], out: &'a mut [u8; 32]]);
impl_async_op!(Sha384Future, Sha384, [data: &'a [u8], out: &'a mut [u8; 48]]);
impl_async_op!(P256KeygenFuture, P256Keygen, [secret_key: &'a mut [u8; 32], public_key: &'a mut [u8; 64]]);
impl_async_op!(P256EcdhFuture, P256Ecdh, [secret_key: &'a [u8; 32], public_key: &'a [u8; 64], shared_secret: &'a mut [u8; 32]]);
impl_async_op!(P256EcdsaSignFuture, P256EcdsaSign, [secret_key: &'a [u8; 32], digest: &'a [u8; 32], signature: &'a mut [u8; 64]]);
impl_async_op!(P256EcdsaVerifyFuture, P256EcdsaVerify, [public_key: &'a [u8; 64], digest: &'a [u8; 32], signature: &'a [u8; 64]]);
impl_async_op!(P384KeygenFuture, P384Keygen, [secret_key: &'a mut [u8; 48], public_key: &'a mut [u8; 96]]);
impl_async_op!(P384EcdhFuture, P384Ecdh, [secret_key: &'a [u8; 48], public_key: &'a [u8; 96], shared_secret: &'a mut [u8; 48]]);
impl_async_op!(P384EcdsaSignFuture, P384EcdsaSign, [secret_key: &'a [u8; 48], digest: &'a [u8; 48], signature: &'a mut [u8; 96]]);
impl_async_op!(P384EcdsaVerifyFuture, P384EcdsaVerify, [public_key: &'a [u8; 96], digest: &'a [u8; 48], signature: &'a [u8; 96]]);
impl_async_op!(RsaVerifyPkcs1v15Sha256Future, RsaVerifyPkcs1v15Sha256, [public_key: &'a [u8], digest: &'a [u8; 32], signature: &'a [u8]]);
impl_async_op!(RsaVerifyPkcs1v15Sha384Future, RsaVerifyPkcs1v15Sha384, [public_key: &'a [u8], digest: &'a [u8; 48], signature: &'a [u8]]);
impl_async_op!(RsaVerifyPkcs1v15Sha512Future, RsaVerifyPkcs1v15Sha512, [public_key: &'a [u8], digest: &'a [u8; 64], signature: &'a [u8]]);
impl_async_op!(RsaVerifyPssSha256Future, RsaVerifyPssSha256, [public_key: &'a [u8], digest: &'a [u8; 32], signature: &'a [u8]]);
impl_async_op!(RsaVerifyPssSha384Future, RsaVerifyPssSha384, [public_key: &'a [u8], digest: &'a [u8; 48], signature: &'a [u8]]);
impl_async_op!(RsaVerifyPssSha512Future, RsaVerifyPssSha512, [public_key: &'a [u8], digest: &'a [u8; 64], signature: &'a [u8]]);

// ------------------------------------------------------------------
// Async future types (usize output)
// ------------------------------------------------------------------
impl_async_size_op!(RsaSignPkcs1v15Sha256Future, RsaSignPkcs1v15Sha256, [private_key: &'a [u8], digest: &'a [u8; 32], signature: &'a mut [u8]]);
impl_async_size_op!(RsaSignPkcs1v15Sha384Future, RsaSignPkcs1v15Sha384, [private_key: &'a [u8], digest: &'a [u8; 48], signature: &'a mut [u8]]);
impl_async_size_op!(RsaSignPkcs1v15Sha512Future, RsaSignPkcs1v15Sha512, [private_key: &'a [u8], digest: &'a [u8; 64], signature: &'a mut [u8]]);
impl_async_size_op!(RsaSignPssSha256Future, RsaSignPssSha256, [private_key: &'a [u8], digest: &'a [u8; 32], signature: &'a mut [u8]]);
impl_async_size_op!(RsaSignPssSha384Future, RsaSignPssSha384, [private_key: &'a [u8], digest: &'a [u8; 48], signature: &'a mut [u8]]);
impl_async_size_op!(RsaSignPssSha512Future, RsaSignPssSha512, [private_key: &'a [u8], digest: &'a [u8; 64], signature: &'a mut [u8]]);

// ------------------------------------------------------------------
// Streaming SHA-256 futures (manual — field names differ from OpKind)
// ------------------------------------------------------------------
pub struct Sha256UpdateFuture<'a> {
    backend: &'a dyn RunnerBackend,
    ctx_handle: crate::queue::ContextHandle,
    data: &'a [u8],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for Sha256UpdateFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this.backend.schedule(crate::queue::OpKind::Sha256Update {
                    ctx_handle: this.ctx_handle,
                    data: this.data,
                })?;
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
    ctx_handle: crate::queue::ContextHandle,
    out: &'a mut [u8; 32],
    handle: Option<crate::queue::OpHandle>,
}

impl Future for Sha256FinalizeFuture<'_> {
    type Output = Result<(), CryptoError>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        match this.handle {
            None => {
                let handle = this
                    .backend
                    .schedule(crate::queue::OpKind::Sha256Finalize {
                        ctx_handle: this.ctx_handle,
                        out: this.out,
                    })?;
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
