use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::queue::ContextHandle;
use crate::runner::RunnerBackend;
use embassy_crypto_driver::{Algorithm, CryptoError};

/// Generate a blocking crypto operation that returns `Result<(), CryptoError>`.
macro_rules! impl_blocking_op {
    ($name:ident, $variant:ident, [ $($arg:ident: $ty:ty),* $(,)? ]) => {
        pub fn $name(&self, $($arg: $ty),*) -> Result<(), CryptoError> {
            self.backend
                .dispatch_blocking(crate::runner::BlockingOp::$variant { $($arg),* })
                .unwrap_or(Err(CryptoError::HardwareError))
        }
    };
}

/// Generate a blocking crypto operation that returns `Result<usize, CryptoError>`.
macro_rules! impl_blocking_size_op {
    ($name:ident, $variant:ident, [ $($arg:ident: $ty:ty),* $(,)? ]) => {
        pub fn $name(&self, $($arg: $ty),*) -> Result<usize, CryptoError> {
            self.backend
                .dispatch_blocking_size(crate::runner::BlockingOpSize::$variant { $($arg),* })
                .unwrap_or(Err(CryptoError::HardwareError))
        }
    };
}

/// Generate an HMAC streaming init method.
macro_rules! impl_hmac_init_op {
    ($name:ident, $algo:expr) => {
        pub fn $name(&self, key: &[u8]) -> Result<ContextHandle, CryptoError> {
            self.backend.try_hmac_init($algo, key)
        }
    };
}

/// Generate an HMAC streaming update method.
macro_rules! impl_hmac_update_op {
    ($name:ident, $algo:expr) => {
        pub fn $name(&self, handle: ContextHandle, data: &[u8]) -> Result<(), CryptoError> {
            self.backend.try_context_update(handle, $algo, data)
        }
    };
}

/// Generate an HMAC streaming finalize method.
macro_rules! impl_hmac_finalize_op {
    ($name:ident, $algo:expr) => {
        pub fn $name(&self, handle: ContextHandle, out: &mut [u8]) -> Result<(), CryptoError> {
            self.backend.try_context_finalize(handle, $algo, out)
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

/// Generate a triplet of blocking streaming-hash methods (init/update/finalize).
macro_rules! impl_streaming_hash {
    ($init:ident, $update:ident, $finalize:ident, $algo:expr, $digest_len:expr) => {
        pub fn $init(&self) -> Result<crate::queue::ContextHandle, CryptoError> {
            self.backend.try_context_init($algo)
        }
        pub fn $update(
            &self,
            ctx: crate::queue::ContextHandle,
            data: &[u8],
        ) -> Result<(), CryptoError> {
            self.backend.try_context_update(ctx, $algo, data)
        }
        pub fn $finalize(
            &self,
            ctx: crate::queue::ContextHandle,
            out: &mut [u8; $digest_len],
        ) -> Result<(), CryptoError> {
            self.backend.try_context_finalize(ctx, $algo, out)
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
    pub fn blocking_rng_fill(&self, dest: &mut [u8]) -> Result<(), CryptoError> {
        if let Some(result) = self.backend.try_rng_fill(dest) {
            return result;
        }
        self.backend
            .dispatch_blocking(crate::runner::BlockingOp::RngFill { dest })
            .unwrap_or(Err(CryptoError::HardwareError))
    }
    impl_blocking_op!(blocking_aes_128_ecb_encrypt, Aes128EcbEncrypt, [block: &mut [u8; 16], key: &[u8; 16]]);
    impl_blocking_op!(blocking_aes_128_ecb_decrypt, Aes128EcbDecrypt, [block: &mut [u8; 16], key: &[u8; 16]]);
    impl_blocking_op!(blocking_aes_128_cmac, Aes128Cmac, [key: &[u8; 16], data: &[u8], out: &mut [u8; 16]]);
    impl_blocking_op!(blocking_aes_ccm_128_encrypt, AesCcm128Encrypt, [key: &[u8; 16], nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8; 16]]);
    impl_blocking_op!(blocking_aes_ccm_128_decrypt, AesCcm128Decrypt, [key: &[u8; 16], nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8; 16]]);
    impl_blocking_op!(blocking_aes_ccm8_128_encrypt, AesCcm8_128Encrypt, [key: &[u8; 16], nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8; 8]]);
    impl_blocking_op!(blocking_aes_ccm8_128_decrypt, AesCcm8_128Decrypt, [key: &[u8; 16], nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8; 8]]);
    impl_blocking_op!(blocking_aes_gcm_128_encrypt, AesGcm128Encrypt, [key: &[u8; 16], nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8; 16]]);
    impl_blocking_op!(blocking_aes_gcm_128_decrypt, AesGcm128Decrypt, [key: &[u8; 16], nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8; 16]]);
    impl_blocking_op!(blocking_aes_gcm_256_encrypt, AesGcm256Encrypt, [key: &[u8; 32], nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8], tag: &mut [u8; 16]]);
    impl_blocking_op!(blocking_aes_gcm_256_decrypt, AesGcm256Decrypt, [key: &[u8; 32], nonce: &[u8], aad: &[u8], ciphertext: &[u8], plaintext: &mut [u8], tag: &[u8; 16]]);
    impl_blocking_op!(blocking_p256_keygen, P256Keygen, [secret_key: &mut [u8; 32], public_key: &mut [u8; 64]]);
    impl_blocking_op!(blocking_p256_ecdh, P256Ecdh, [secret_key: &[u8; 32], public_key: &[u8; 64], shared_secret: &mut [u8; 32]]);
    impl_blocking_op!(blocking_p256_ecdsa_sign, P256EcdsaSign, [secret_key: &[u8; 32], digest: &[u8; 32], signature: &mut [u8; 64]]);
    impl_blocking_op!(blocking_p256_ecdsa_verify, P256EcdsaVerify, [public_key: &[u8; 64], digest: &[u8; 32], signature: &[u8; 64]]);
    impl_blocking_op!(blocking_p384_keygen, P384Keygen, [secret_key: &mut [u8; 48], public_key: &mut [u8; 96]]);
    impl_blocking_op!(blocking_p384_ecdh, P384Ecdh, [secret_key: &[u8; 48], public_key: &[u8; 96], shared_secret: &mut [u8; 48]]);
    impl_blocking_op!(blocking_p384_ecdsa_sign, P384EcdsaSign, [secret_key: &[u8; 48], digest: &[u8; 48], signature: &mut [u8; 96]]);
    impl_blocking_op!(blocking_p384_ecdsa_verify, P384EcdsaVerify, [public_key: &[u8; 96], digest: &[u8; 48], signature: &[u8; 96]]);

    impl_blocking_size_op!(blocking_rsa_sign_pkcs1v15_sha256, RsaSignPkcs1v15Sha256, [private_key: &[u8], digest: &[u8; 32], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pkcs1v15_sha256, RsaVerifyPkcs1v15Sha256, [public_key: &[u8], digest: &[u8; 32], signature: &[u8]]);
    impl_blocking_size_op!(blocking_rsa_sign_pkcs1v15_sha384, RsaSignPkcs1v15Sha384, [private_key: &[u8], digest: &[u8; 48], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pkcs1v15_sha384, RsaVerifyPkcs1v15Sha384, [public_key: &[u8], digest: &[u8; 48], signature: &[u8]]);
    impl_blocking_size_op!(blocking_rsa_sign_pkcs1v15_sha512, RsaSignPkcs1v15Sha512, [private_key: &[u8], digest: &[u8; 64], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pkcs1v15_sha512, RsaVerifyPkcs1v15Sha512, [public_key: &[u8], digest: &[u8; 64], signature: &[u8]]);
    impl_blocking_size_op!(blocking_rsa_sign_pss_sha256, RsaSignPssSha256, [private_key: &[u8], digest: &[u8; 32], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pss_sha256, RsaVerifyPssSha256, [public_key: &[u8], digest: &[u8; 32], signature: &[u8]]);
    impl_blocking_size_op!(blocking_rsa_sign_pss_sha384, RsaSignPssSha384, [private_key: &[u8], digest: &[u8; 48], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pss_sha384, RsaVerifyPssSha384, [public_key: &[u8], digest: &[u8; 48], signature: &[u8]]);
    impl_blocking_size_op!(blocking_rsa_sign_pss_sha512, RsaSignPssSha512, [private_key: &[u8], digest: &[u8; 64], signature: &mut [u8]]);
    impl_blocking_op!(blocking_rsa_verify_pss_sha512, RsaVerifyPssSha512, [public_key: &[u8], digest: &[u8; 64], signature: &[u8]]);

    // ------------------------------------------------------------------
    // Async constructors
    // ------------------------------------------------------------------
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
    // Blocking streaming hash operations
    // ------------------------------------------------------------------
    impl_streaming_hash!(sha1_init, sha1_update, sha1_finalize, Algorithm::SHA1, 20);
    impl_streaming_hash!(md5_init, md5_update, md5_finalize, Algorithm::MD5, 16);
    impl_streaming_hash!(
        sha224_init,
        sha224_update,
        sha224_finalize,
        Algorithm::SHA224,
        28
    );
    impl_streaming_hash!(
        sha256_init,
        sha256_update,
        sha256_finalize,
        Algorithm::SHA256,
        32
    );
    impl_streaming_hash!(
        sha384_init,
        sha384_update,
        sha384_finalize,
        Algorithm::SHA384,
        48
    );
    impl_streaming_hash!(
        sha512_224_init,
        sha512_224_update,
        sha512_224_finalize,
        Algorithm::SHA512_224,
        28
    );
    impl_streaming_hash!(
        sha512_256_init,
        sha512_256_update,
        sha512_256_finalize,
        Algorithm::SHA512_256,
        32
    );
    impl_streaming_hash!(
        sha512_init,
        sha512_update,
        sha512_finalize,
        Algorithm::SHA512,
        64
    );

    // ------------------------------------------------------------------
    // HMAC streaming operations
    // ------------------------------------------------------------------
    impl_hmac_init_op!(hmac_sha256_init, Algorithm::HmacSha256);
    impl_hmac_update_op!(hmac_sha256_update, Algorithm::HmacSha256);
    impl_hmac_finalize_op!(hmac_sha256_finalize, Algorithm::HmacSha256);

    impl_hmac_init_op!(hmac_sha384_init, Algorithm::HmacSha384);
    impl_hmac_update_op!(hmac_sha384_update, Algorithm::HmacSha384);
    impl_hmac_finalize_op!(hmac_sha384_finalize, Algorithm::HmacSha384);

    impl_hmac_init_op!(hmac_sha512_init, Algorithm::HmacSha512);
    impl_hmac_update_op!(hmac_sha512_update, Algorithm::HmacSha512);
    impl_hmac_finalize_op!(hmac_sha512_finalize, Algorithm::HmacSha512);
}

// ------------------------------------------------------------------
// Async future types (unit output)
// ------------------------------------------------------------------
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
