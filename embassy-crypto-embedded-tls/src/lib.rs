#![no_std]

use core::marker::PhantomData;

use embassy_crypto::{AesGcm128, AesGcm256};
use embedded_tls::{
    Aes128GcmSha256, Aes256GcmSha384, CryptoProvider, NamedGroup,
    crypto_traits::{TlsAead, TlsHash, TlsHmac},
    TlsError,
};
use generic_array::GenericArray;

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
    inner: AesGcm128,
}

impl EmbassyAead128 {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        Ok(Self {
            inner: AesGcm128::new(key).map_err(|_| TlsError::CryptoError)?,
        })
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
        if tag.len() != 16 {
            return Err(TlsError::CryptoError);
        }
        let mut tag_arr = [0u8; 16];
        self.inner
            .encrypt_in_place(nonce, aad, buffer, &mut tag_arr)
            .map_err(|_| TlsError::CryptoError)?;
        tag.copy_from_slice(&tag_arr);
        Ok(())
    }

    fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), TlsError> {
        if tag.len() != 16 {
            return Err(TlsError::CryptoError);
        }
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        self.inner
            .decrypt_in_place(nonce, aad, buffer, &tag_arr)
            .map_err(|_| TlsError::CryptoError)
    }
}

/// AES-256-GCM AEAD implementing [`TlsAead`], backed by `embassy-crypto`.
pub struct EmbassyAead256 {
    inner: AesGcm256,
}

impl EmbassyAead256 {
    pub fn new(key: &[u8]) -> Result<Self, TlsError> {
        Ok(Self {
            inner: AesGcm256::new(key).map_err(|_| TlsError::CryptoError)?,
        })
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
        if tag.len() != 16 {
            return Err(TlsError::CryptoError);
        }
        let mut tag_arr = [0u8; 16];
        self.inner
            .encrypt_in_place(nonce, aad, buffer, &mut tag_arr)
            .map_err(|_| TlsError::CryptoError)?;
        tag.copy_from_slice(&tag_arr);
        Ok(())
    }

    fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8],
    ) -> Result<(), TlsError> {
        if tag.len() != 16 {
            return Err(TlsError::CryptoError);
        }
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        self.inner
            .decrypt_in_place(nonce, aad, buffer, &tag_arr)
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

impl CryptoProvider for EmbassyCryptoProvider<Aes128GcmSha256> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = heapless::Vec<u8, 128>;
    type Hash = EmbassyHash256;
    type Hmac = EmbassyHmac256;
    type Aead = EmbassyAead128;

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        struct NoRng;
        impl rand_core::RngCore for NoRng {
            fn next_u32(&mut self) -> u32 { panic!("no rng") }
            fn next_u64(&mut self) -> u64 { panic!("no rng") }
            fn fill_bytes(&mut self, _dest: &mut [u8]) { panic!("no rng") }
            fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
                panic!("no rng")
            }
        }
        impl rand_core::CryptoRng for NoRng {}
        NoRng
    }

    fn aead(&mut self, key: &[u8]) -> Result<Self::Aead, TlsError> {
        EmbassyAead128::new(key)
    }

    fn ecdh(
        &mut self,
        _group: NamedGroup,
        _secret_key: &[u8],
        _peer_public: &[u8],
        _shared_secret: &mut [u8],
    ) -> Result<(), TlsError> {
        unimplemented!("EmbassyCryptoProvider does not provide ECDH; compose with another provider")
    }

    fn keygen(
        &mut self,
        _group: NamedGroup,
        _secret_key: &mut [u8],
        _public_key: &mut [u8],
    ) -> Result<(), TlsError> {
        unimplemented!("EmbassyCryptoProvider does not provide keygen; compose with another provider")
    }
}

impl CryptoProvider for EmbassyCryptoProvider<Aes256GcmSha384> {
    type CipherSuite = Aes256GcmSha384;
    type Signature = heapless::Vec<u8, 128>;
    type Hash = EmbassyHash384;
    type Hmac = EmbassyHmac384;
    type Aead = EmbassyAead256;

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        struct NoRng;
        impl rand_core::RngCore for NoRng {
            fn next_u32(&mut self) -> u32 { panic!("no rng") }
            fn next_u64(&mut self) -> u64 { panic!("no rng") }
            fn fill_bytes(&mut self, _dest: &mut [u8]) { panic!("no rng") }
            fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
                panic!("no rng")
            }
        }
        impl rand_core::CryptoRng for NoRng {}
        NoRng
    }

    fn aead(&mut self, key: &[u8]) -> Result<Self::Aead, TlsError> {
        EmbassyAead256::new(key)
    }

    fn ecdh(
        &mut self,
        _group: NamedGroup,
        _secret_key: &[u8],
        _peer_public: &[u8],
        _shared_secret: &mut [u8],
    ) -> Result<(), TlsError> {
        unimplemented!("EmbassyCryptoProvider does not provide ECDH; compose with another provider")
    }

    fn keygen(
        &mut self,
        _group: NamedGroup,
        _secret_key: &mut [u8],
        _public_key: &mut [u8],
    ) -> Result<(), TlsError> {
        unimplemented!("EmbassyCryptoProvider does not provide keygen; compose with another provider")
    }
}
