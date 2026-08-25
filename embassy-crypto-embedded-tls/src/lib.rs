#![no_std]

use core::marker::PhantomData;

use embassy_crypto::{dispatch_blocking, CryptoError};
use embassy_crypto_driver::BlockingOp;
use embedded_tls::{
    config::TlsCipherSuite,
    crypto_traits::{TlsAead, TlsHash, TlsHmac},
    TlsError,
};
use generic_array::GenericArray;
use typenum::Unsigned;

// ------------------------------------------------------------------
// Hash wrappers
// ------------------------------------------------------------------

/// SHA-256 hash implementing [`TlsHash`].
#[derive(Clone)]
pub struct EmbassyHash256 {
    inner: embassy_crypto::Sha256,
}

impl EmbassyHash256 {
    pub fn new() -> Self {
        Self {
            inner: embassy_crypto::Sha256::new().expect("embassy-crypto SHA-256 unavailable"),
        }
    }
}

impl TlsHash for EmbassyHash256 {
    type OutputSize = typenum::U32;

    fn new() -> Self {
        Self::new()
    }

    fn reset(&mut self) {
        self.inner = embassy_crypto::Sha256::new()
            .expect("embassy-crypto SHA-256 unavailable");
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data).expect("SHA-256 update failed");
    }

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.inner.finalize_into(out).expect("SHA-256 finalize failed");
    }
}

/// SHA-384 hash implementing [`TlsHash`].
#[derive(Clone)]
pub struct EmbassyHash384 {
    inner: embassy_crypto::Sha384,
}

impl EmbassyHash384 {
    pub fn new() -> Self {
        Self {
            inner: embassy_crypto::Sha384::new().expect("embassy-crypto SHA-384 unavailable"),
        }
    }
}

impl TlsHash for EmbassyHash384 {
    type OutputSize = typenum::U48;

    fn new() -> Self {
        Self::new()
    }

    fn reset(&mut self) {
        self.inner = embassy_crypto::Sha384::new()
            .expect("embassy-crypto SHA-384 unavailable");
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data).expect("SHA-384 update failed");
    }

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.inner.finalize_into(out).expect("SHA-384 finalize failed");
    }
}

// ------------------------------------------------------------------
// HMAC wrappers
// ------------------------------------------------------------------

/// HMAC-SHA-256 implementing [`TlsHmac`].
#[derive(Clone)]
pub struct EmbassyHmac256 {
    inner: embassy_crypto::HmacSha256,
}

impl TlsHmac for EmbassyHmac256 {
    type OutputSize = typenum::U32;

    fn new(key: &[u8]) -> Result<Self, TlsError> {
        Ok(Self {
            inner: embassy_crypto::HmacSha256::new_from_slice(key)
                .map_err(|_| TlsError::CryptoError)?,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data).expect("HMAC-SHA-256 update failed");
    }

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.inner.finalize_into(out).expect("HMAC-SHA-256 finalize failed");
    }
}

/// HMAC-SHA-384 implementing [`TlsHmac`].
#[derive(Clone)]
pub struct EmbassyHmac384 {
    inner: embassy_crypto::HmacSha384,
}

impl TlsHmac for EmbassyHmac384 {
    type OutputSize = typenum::U48;

    fn new(key: &[u8]) -> Result<Self, TlsError> {
        Ok(Self {
            inner: embassy_crypto::HmacSha384::new_from_slice(key)
                .map_err(|_| TlsError::CryptoError)?,
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data).expect("HMAC-SHA-384 update failed");
    }

    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        self.inner.finalize_into(out).expect("HMAC-SHA-384 finalize failed");
    }
}

// ------------------------------------------------------------------
// AEAD wrappers
// ------------------------------------------------------------------

/// AES-128-GCM AEAD implementing [`TlsAead`], backed by `embassy-crypto`.
pub struct EmbassyAead128 {
    key: [u8; 16],
}

impl EmbassyAead128 {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 16 {
            return Err(TlsError::CryptoError);
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }
}

impl TlsAead for EmbassyAead128 {
    fn encrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), TlsError> {
        let mut tag_buf = [0u8; 16];
        dispatch_blocking(BlockingOp::AesGcm128Encrypt {
            key: &self.key,
            nonce,
            aad,
            plaintext: buffer,
            ciphertext: buffer,
            tag: &mut tag_buf,
        })
        .map_err(|_| TlsError::CryptoError)?;
        tag.copy_from_slice(&tag_buf);
        Ok(())
    }

    fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), TlsError> {
        let mut tag_buf = [0u8; 16];
        if tag.len() != 16 {
            return Err(TlsError::CryptoError);
        }
        tag_buf.copy_from_slice(tag);
        dispatch_blocking(BlockingOp::AesGcm128Decrypt {
            key: &self.key,
            nonce,
            aad,
            ciphertext: buffer,
            plaintext: buffer,
            tag: &tag_buf,
        })
        .map_err(|_| TlsError::CryptoError)
    }
}

/// AES-256-GCM AEAD implementing [`TlsAead`], backed by `embassy-crypto`.
pub struct EmbassyAead256 {
    key: [u8; 32],
}

impl EmbassyAead256 {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        if key.len() != 32 {
            return Err(TlsError::CryptoError);
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }
}

impl TlsAead for EmbassyAead256 {
    fn encrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8],
    ) -> Result<(), TlsError> {
        let mut tag_buf = [0u8; 16];
        dispatch_blocking(BlockingOp::AesGcm256Encrypt {
            key: &self.key,
            nonce,
            aad,
            plaintext: buffer,
            ciphertext: buffer,
            tag: &mut tag_buf,
        })
        .map_err(|_| TlsError::CryptoError)?;
        tag.copy_from_slice(&tag_buf);
        Ok(())
    }

    fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), TlsError> {
        let mut tag_buf = [0u8; 16];
        if tag.len() != 16 {
            return Err(TlsError::CryptoError);
        }
        tag_buf.copy_from_slice(tag);
        dispatch_blocking(BlockingOp::AesGcm256Decrypt {
            key: &self.key,
            nonce,
            aad,
            ciphertext: buffer,
            plaintext: buffer,
            tag: &tag_buf,
        })
        .map_err(|_| TlsError::CryptoError)
    }
}

// ------------------------------------------------------------------
// CryptoProvider
// ------------------------------------------------------------------

/// [`CryptoProvider`] implementation backed entirely by `embassy-crypto`.
///
/// RNG and ECDH are **not** implemented — delegate those to a separate
/// provider or use the software fallback in `embedded-tls`.
pub struct EmbassyCryptoProvider<CipherSuite> {
    _marker: PhantomData<CipherSuite>,
}

impl<CipherSuite> EmbassyCryptoProvider<CipherSuite> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl embedded_tls::CryptoProvider for EmbassyCryptoProvider<embedded_tls::Aes128GcmSha256> {
    type CipherSuite = embedded_tls::Aes128GcmSha256;
    type Signature = heapless::Vec<u8, 128>;
    type Hash = EmbassyHash256;
    type Hmac = EmbassyHmac256;
    type Aead = EmbassyAead128;

    fn rng(&mut self) -> impl rand_core::CryptoRngCore {
        unimplemented!("EmbassyCryptoProvider does not provide RNG; compose with another provider")
    }

    fn aead(&mut self, key: &[u8]) -> Result<Self::Aead, TlsError> {
        EmbassyAead128::new(key)
    }

    fn ecdh(
        &mut self,
        _group: embedded_tls::extensions::extension_data::supported_groups::NamedGroup,
        _secret_key: &[u8],
        _peer_public: &[u8],
        _shared_secret: &mut [u8],
    ) -> Result<(), TlsError> {
        unimplemented!("EmbassyCryptoProvider does not provide ECDH; compose with another provider")
    }

    fn keygen(
        &mut self,
        _group: embedded_tls::extensions::extension_data::supported_groups::NamedGroup,
        _secret_key: &mut [u8],
        _public_key: &mut [u8],
    ) -> Result<(), TlsError> {
        unimplemented!("EmbassyCryptoProvider does not provide keygen; compose with another provider")
    }
}

impl embedded_tls::CryptoProvider for EmbassyCryptoProvider<embedded_tls::Aes256GcmSha384> {
    type CipherSuite = embedded_tls::Aes256GcmSha384;
    type Signature = heapless::Vec<u8, 128>;
    type Hash = EmbassyHash384;
    type Hmac = EmbassyHmac384;
    type Aead = EmbassyAead256;

    fn rng(&mut self) -> impl rand_core::CryptoRngCore {
        unimplemented!("EmbassyCryptoProvider does not provide RNG; compose with another provider")
    }

    fn aead(&mut self, key: &[u8]) -> Result<Self::Aead, TlsError> {
        EmbassyAead256::new(key)
    }

    fn ecdh(
        &mut self,
        _group: embedded_tls::extensions::extension_data::supported_groups::NamedGroup,
        _secret_key: &[u8],
        _peer_public: &[u8],
        _shared_secret: &mut [u8],
    ) -> Result<(), TlsError> {
        unimplemented!("EmbassyCryptoProvider does not provide ECDH; compose with another provider")
    }

    fn keygen(
        &mut self,
        _group: embedded_tls::extensions::extension_data::supported_groups::NamedGroup,
        _secret_key: &mut [u8],
        _public_key: &mut [u8],
    ) -> Result<(), TlsError> {
        unimplemented!("EmbassyCryptoProvider does not provide keygen; compose with another provider")
    }
}
