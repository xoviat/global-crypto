//! Rich algorithm and data types.
//!
//! These types live *above* the `dyn CryptoDriver` boundary.
//! They provide algorithm-tagging to prevent mixing keys across algorithms.
//!
//! Note: Stable Rust does not allow generic parameters in const array sizes
//! (`[u8; A::KEY_LEN]`). We use max-size backing arrays + PhantomData instead.
//! The `as_bytes()` method returns a correctly-sized slice.

use core::marker::PhantomData;

use crate::CryptoError;

mod sealed {
    pub trait Sealed {}
}

// ============================================================================
// Max sizes for backing arrays
// ============================================================================

pub(crate) const MAX_AEAD_KEY: usize = 32;
pub(crate) const MAX_AEAD_NONCE: usize = 13;
pub(crate) const MAX_AEAD_TAG: usize = 16;
pub(crate) const MAX_HASH_OUT: usize = 64;
#[allow(dead_code)]
pub(crate) const MAX_HASH_STATE: usize = 256;
#[allow(dead_code)]
pub(crate) const MAX_HMAC_KEY: usize = 128;
pub(crate) const MAX_HMAC_OUT: usize = 64;
pub(crate) const MAX_DH_PUBKEY: usize = 97; // uncompressed P-384
pub(crate) const MAX_DH_SECKEY: usize = 48;
pub(crate) const MAX_DH_SHARED: usize = 48;
pub(crate) const MAX_CORDIC_IN: usize = 16;
pub(crate) const MAX_CORDIC_OUT: usize = 16;
pub(crate) const MAX_SIGN_SIG: usize = 96;
pub(crate) const MAX_SIGN_SECKEY: usize = 48;
pub(crate) const MAX_SIGN_PUBKEY: usize = 97; // uncompressed P-384
pub(crate) const MAX_CIPHER_KEY: usize = 32;
pub(crate) const MAX_CIPHER_IV: usize = 16;
pub(crate) const MAX_CRC_OUT: usize = 4;

// ============================================================================
// Algorithm IDs (dyn-boundary enums)
// ============================================================================

/// AEAD algorithm identifier for the object-safe driver boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AeadAlgorithmId {
    AesCcm16_64_128,
    AesCcm16_128_128,
    Aes128Gcm,
    Aes256Gcm,
}

/// Hash algorithm identifier for the object-safe driver boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlgorithmId {
    Sha256,
    Sha384,
    Sha512,
}

/// HMAC algorithm identifier for the object-safe driver boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HmacAlgorithmId {
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

/// Diffie-Hellman algorithm identifier for the object-safe driver boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DhAlgorithmId {
    EcdhP256,
    EcdhP384,
    X25519,
    EcdhP256Uncompressed,
}

/// CORDIC algorithm identifier for the object-safe driver boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CordicAlgorithmId {
    SinCos,
    Atan2,
    Hypot,
}

/// Digital signature algorithm identifier for the object-safe driver boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignAlgorithmId {
    EcdsaP256,
    EcdsaP384,
}

/// Signature verification algorithm identifier for the object-safe driver boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VerifyAlgorithmId {
    EcdsaP256,
    EcdsaP384,
}

/// Raw symmetric cipher algorithm identifier for the object-safe driver boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CipherAlgorithmId {
    Aes128Ecb,
    Aes256Ecb,
    Aes128Cbc,
    Aes256Cbc,
    Aes128Ctr,
    Aes256Ctr,
}

/// CRC algorithm identifier for the object-safe driver boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CrcAlgorithmId {
    Crc32,
    Crc32C,
    Crc16,
    Crc8,
}

// ============================================================================
// Rich algorithm traits (compile-time parameters as associated consts)
// ============================================================================

/// Trait for AEAD algorithms known to the global crypto system.
pub trait AeadAlgorithm: Copy + sealed::Sealed {
    const KEY_LEN: usize;
    const NONCE_LEN: usize;
    const TAG_LEN: usize;
    const ID: AeadAlgorithmId;
}

/// Trait for hash algorithms known to the global crypto system.
pub trait HashAlgorithm: Copy + sealed::Sealed {
    const OUTPUT_LEN: usize;
    const ID: HashAlgorithmId;
}

/// Trait for HMAC algorithms known to the global crypto system.
pub trait HmacAlgorithm: Copy + sealed::Sealed {
    const KEY_LEN: usize;
    const OUTPUT_LEN: usize;
    const ID: HmacAlgorithmId;
}

/// Trait for DH algorithms known to the global crypto system.
pub trait DhAlgorithm: Copy + sealed::Sealed {
    const SECRET_KEY_LEN: usize;
    const PUBLIC_KEY_LEN: usize;
    const SHARED_SECRET_LEN: usize;
    const ID: DhAlgorithmId;
}

/// Trait for CORDIC algorithms known to the global crypto system.
pub trait CordicAlgorithm: Copy + sealed::Sealed {
    const INPUT_LEN: usize;
    const OUTPUT_LEN: usize;
    const ID: CordicAlgorithmId;
}

/// Trait for digital signature algorithms known to the global crypto system.
pub trait SignAlgorithm: Copy + sealed::Sealed {
    const SECRET_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;
    const ID: SignAlgorithmId;
}

/// Trait for signature verification algorithms known to the global crypto system.
pub trait VerifyAlgorithm: Copy + sealed::Sealed {
    const PUBLIC_KEY_LEN: usize;
    const SIGNATURE_LEN: usize;
    const ID: VerifyAlgorithmId;
}

/// Trait for raw symmetric cipher algorithms known to the global crypto system.
pub trait CipherAlgorithm: Copy + sealed::Sealed {
    const KEY_LEN: usize;
    const IV_LEN: usize;
    const ID: CipherAlgorithmId;
}

/// Trait for CRC algorithms known to the global crypto system.
pub trait CrcAlgorithm: Copy + sealed::Sealed {
    const OUTPUT_LEN: usize;
    const ID: CrcAlgorithmId;
}

// ============================================================================
// Concrete algorithm types
// ============================================================================

/// AES-CCM-16-64-128 (COSE algorithm 10).
#[derive(Clone, Copy)]
pub struct AesCcm16_64_128;
impl sealed::Sealed for AesCcm16_64_128 {}
impl AeadAlgorithm for AesCcm16_64_128 {
    const KEY_LEN: usize = 16;
    const NONCE_LEN: usize = 13;
    const TAG_LEN: usize = 8;
    const ID: AeadAlgorithmId = AeadAlgorithmId::AesCcm16_64_128;
}

/// AES-CCM-16-128-128 (COSE algorithm 30).
#[derive(Clone, Copy)]
pub struct AesCcm16_128_128;
impl sealed::Sealed for AesCcm16_128_128 {}
impl AeadAlgorithm for AesCcm16_128_128 {
    const KEY_LEN: usize = 16;
    const NONCE_LEN: usize = 13;
    const TAG_LEN: usize = 16;
    const ID: AeadAlgorithmId = AeadAlgorithmId::AesCcm16_128_128;
}

/// AES-128-GCM (COSE algorithm 1).
#[derive(Clone, Copy)]
pub struct Aes128Gcm;
impl sealed::Sealed for Aes128Gcm {}
impl AeadAlgorithm for Aes128Gcm {
    const KEY_LEN: usize = 16;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;
    const ID: AeadAlgorithmId = AeadAlgorithmId::Aes128Gcm;
}

/// AES-256-GCM (COSE algorithm 3).
#[derive(Clone, Copy)]
pub struct Aes256Gcm;
impl sealed::Sealed for Aes256Gcm {}
impl AeadAlgorithm for Aes256Gcm {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;
    const ID: AeadAlgorithmId = AeadAlgorithmId::Aes256Gcm;
}

/// SHA-256 (COSE algorithm -16).
#[derive(Clone, Copy)]
pub struct Sha256;
impl sealed::Sealed for Sha256 {}
impl HashAlgorithm for Sha256 {
    const OUTPUT_LEN: usize = 32;
    const ID: HashAlgorithmId = HashAlgorithmId::Sha256;
}

/// SHA-384 (COSE algorithm -43).
#[derive(Clone, Copy)]
pub struct Sha384;
impl sealed::Sealed for Sha384 {}
impl HashAlgorithm for Sha384 {
    const OUTPUT_LEN: usize = 48;
    const ID: HashAlgorithmId = HashAlgorithmId::Sha384;
}

/// SHA-512 (COSE algorithm -44).
#[derive(Clone, Copy)]
pub struct Sha512;
impl sealed::Sealed for Sha512 {}
impl HashAlgorithm for Sha512 {
    const OUTPUT_LEN: usize = 64;
    const ID: HashAlgorithmId = HashAlgorithmId::Sha512;
}

/// HMAC-SHA-256 (COSE algorithm 5).
#[derive(Clone, Copy)]
pub struct HmacSha256;
impl sealed::Sealed for HmacSha256 {}
impl HmacAlgorithm for HmacSha256 {
    const KEY_LEN: usize = 64;
    const OUTPUT_LEN: usize = 32;
    const ID: HmacAlgorithmId = HmacAlgorithmId::HmacSha256;
}

/// HMAC-SHA-384 (COSE algorithm 6).
#[derive(Clone, Copy)]
pub struct HmacSha384;
impl sealed::Sealed for HmacSha384 {}
impl HmacAlgorithm for HmacSha384 {
    const KEY_LEN: usize = 128;
    const OUTPUT_LEN: usize = 48;
    const ID: HmacAlgorithmId = HmacAlgorithmId::HmacSha384;
}

/// HMAC-SHA-512 (COSE algorithm 7).
#[derive(Clone, Copy)]
pub struct HmacSha512;
impl sealed::Sealed for HmacSha512 {}
impl HmacAlgorithm for HmacSha512 {
    const KEY_LEN: usize = 128;
    const OUTPUT_LEN: usize = 64;
    const ID: HmacAlgorithmId = HmacAlgorithmId::HmacSha512;
}

/// ECDH on P-256 (COSE curve 1), compressed public key (33 bytes).
#[derive(Clone, Copy)]
pub struct EcdhP256;
impl sealed::Sealed for EcdhP256 {}
impl DhAlgorithm for EcdhP256 {
    const SECRET_KEY_LEN: usize = 32;
    const PUBLIC_KEY_LEN: usize = 33; // compressed
    const SHARED_SECRET_LEN: usize = 32;
    const ID: DhAlgorithmId = DhAlgorithmId::EcdhP256;
}

/// ECDH on P-256 with uncompressed public keys (65 bytes).
#[derive(Clone, Copy)]
pub struct EcdhP256Uncompressed;
impl sealed::Sealed for EcdhP256Uncompressed {}
impl DhAlgorithm for EcdhP256Uncompressed {
    const SECRET_KEY_LEN: usize = 32;
    const PUBLIC_KEY_LEN: usize = 65; // uncompressed
    const SHARED_SECRET_LEN: usize = 32;
    const ID: DhAlgorithmId = DhAlgorithmId::EcdhP256Uncompressed;
}

/// ECDH on P-384 (COSE curve 2).
#[derive(Clone, Copy)]
pub struct EcdhP384;
impl sealed::Sealed for EcdhP384 {}
impl DhAlgorithm for EcdhP384 {
    const SECRET_KEY_LEN: usize = 48;
    const PUBLIC_KEY_LEN: usize = 49; // compressed
    const SHARED_SECRET_LEN: usize = 48;
    const ID: DhAlgorithmId = DhAlgorithmId::EcdhP384;
}

/// X25519 (COSE curve 4).
#[derive(Clone, Copy)]
pub struct X25519;
impl sealed::Sealed for X25519 {}
impl DhAlgorithm for X25519 {
    const SECRET_KEY_LEN: usize = 32;
    const PUBLIC_KEY_LEN: usize = 32;
    const SHARED_SECRET_LEN: usize = 32;
    const ID: DhAlgorithmId = DhAlgorithmId::X25519;
}

/// CORDIC sin/cos.
#[derive(Clone, Copy)]
pub struct CordicSinCos;
impl sealed::Sealed for CordicSinCos {}
impl CordicAlgorithm for CordicSinCos {
    const INPUT_LEN: usize = 4;
    const OUTPUT_LEN: usize = 8;
    const ID: CordicAlgorithmId = CordicAlgorithmId::SinCos;
}

/// CORDIC atan2.
#[derive(Clone, Copy)]
pub struct CordicAtan2;
impl sealed::Sealed for CordicAtan2 {}
impl CordicAlgorithm for CordicAtan2 {
    const INPUT_LEN: usize = 8;
    const OUTPUT_LEN: usize = 4;
    const ID: CordicAlgorithmId = CordicAlgorithmId::Atan2;
}

/// CORDIC hypot.
#[derive(Clone, Copy)]
pub struct CordicHypot;
impl sealed::Sealed for CordicHypot {}
impl CordicAlgorithm for CordicHypot {
    const INPUT_LEN: usize = 8;
    const OUTPUT_LEN: usize = 4;
    const ID: CordicAlgorithmId = CordicAlgorithmId::Hypot;
}

/// ECDSA on P-256.
#[derive(Clone, Copy)]
pub struct EcdsaP256;
impl sealed::Sealed for EcdsaP256 {}
impl SignAlgorithm for EcdsaP256 {
    const SECRET_KEY_LEN: usize = 32;
    const SIGNATURE_LEN: usize = 64;
    const ID: SignAlgorithmId = SignAlgorithmId::EcdsaP256;
}
impl VerifyAlgorithm for EcdsaP256 {
    const PUBLIC_KEY_LEN: usize = 33; // compressed
    const SIGNATURE_LEN: usize = 64;
    const ID: VerifyAlgorithmId = VerifyAlgorithmId::EcdsaP256;
}

/// ECDSA on P-384.
#[derive(Clone, Copy)]
pub struct EcdsaP384;
impl sealed::Sealed for EcdsaP384 {}
impl SignAlgorithm for EcdsaP384 {
    const SECRET_KEY_LEN: usize = 48;
    const SIGNATURE_LEN: usize = 96;
    const ID: SignAlgorithmId = SignAlgorithmId::EcdsaP384;
}
impl VerifyAlgorithm for EcdsaP384 {
    const PUBLIC_KEY_LEN: usize = 49; // compressed
    const SIGNATURE_LEN: usize = 96;
    const ID: VerifyAlgorithmId = VerifyAlgorithmId::EcdsaP384;
}

/// AES-128-ECB.
#[derive(Clone, Copy)]
pub struct Aes128Ecb;
impl sealed::Sealed for Aes128Ecb {}
impl CipherAlgorithm for Aes128Ecb {
    const KEY_LEN: usize = 16;
    const IV_LEN: usize = 0;
    const ID: CipherAlgorithmId = CipherAlgorithmId::Aes128Ecb;
}

/// AES-256-ECB.
#[derive(Clone, Copy)]
pub struct Aes256Ecb;
impl sealed::Sealed for Aes256Ecb {}
impl CipherAlgorithm for Aes256Ecb {
    const KEY_LEN: usize = 32;
    const IV_LEN: usize = 0;
    const ID: CipherAlgorithmId = CipherAlgorithmId::Aes256Ecb;
}

/// AES-128-CBC.
#[derive(Clone, Copy)]
pub struct Aes128Cbc;
impl sealed::Sealed for Aes128Cbc {}
impl CipherAlgorithm for Aes128Cbc {
    const KEY_LEN: usize = 16;
    const IV_LEN: usize = 16;
    const ID: CipherAlgorithmId = CipherAlgorithmId::Aes128Cbc;
}

/// AES-256-CBC.
#[derive(Clone, Copy)]
pub struct Aes256Cbc;
impl sealed::Sealed for Aes256Cbc {}
impl CipherAlgorithm for Aes256Cbc {
    const KEY_LEN: usize = 32;
    const IV_LEN: usize = 16;
    const ID: CipherAlgorithmId = CipherAlgorithmId::Aes256Cbc;
}

/// AES-128-CTR.
#[derive(Clone, Copy)]
pub struct Aes128Ctr;
impl sealed::Sealed for Aes128Ctr {}
impl CipherAlgorithm for Aes128Ctr {
    const KEY_LEN: usize = 16;
    const IV_LEN: usize = 16;
    const ID: CipherAlgorithmId = CipherAlgorithmId::Aes128Ctr;
}

/// AES-256-CTR.
#[derive(Clone, Copy)]
pub struct Aes256Ctr;
impl sealed::Sealed for Aes256Ctr {}
impl CipherAlgorithm for Aes256Ctr {
    const KEY_LEN: usize = 32;
    const IV_LEN: usize = 16;
    const ID: CipherAlgorithmId = CipherAlgorithmId::Aes256Ctr;
}

/// CRC-32 (IEEE 802.3).
#[derive(Clone, Copy)]
pub struct Crc32;
impl sealed::Sealed for Crc32 {}
impl CrcAlgorithm for Crc32 {
    const OUTPUT_LEN: usize = 4;
    const ID: CrcAlgorithmId = CrcAlgorithmId::Crc32;
}

/// CRC-32C (Castagnoli).
#[derive(Clone, Copy)]
pub struct Crc32C;
impl sealed::Sealed for Crc32C {}
impl CrcAlgorithm for Crc32C {
    const OUTPUT_LEN: usize = 4;
    const ID: CrcAlgorithmId = CrcAlgorithmId::Crc32C;
}

/// CRC-16 (CCITT / ModBus).
#[derive(Clone, Copy)]
pub struct Crc16;
impl sealed::Sealed for Crc16 {}
impl CrcAlgorithm for Crc16 {
    const OUTPUT_LEN: usize = 2;
    const ID: CrcAlgorithmId = CrcAlgorithmId::Crc16;
}

/// CRC-8 (SMBus).
#[derive(Clone, Copy)]
pub struct Crc8;
impl sealed::Sealed for Crc8 {}
impl CrcAlgorithm for Crc8 {
    const OUTPUT_LEN: usize = 1;
    const ID: CrcAlgorithmId = CrcAlgorithmId::Crc8;
}

// ============================================================================
// Rich data types (algorithm-parameterised, max-size backing arrays)
// ============================================================================

/// AEAD key with compile-time algorithm binding.
pub struct AeadKey<A: AeadAlgorithm> {
    bytes: [u8; MAX_AEAD_KEY],
    _phantom: PhantomData<A>,
}

impl<A: AeadAlgorithm> AeadKey<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::KEY_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_AEAD_KEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::KEY_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_AEAD_KEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_AEAD_KEY],
            _phantom: PhantomData,
        }
    }
}

impl<A: AeadAlgorithm> Clone for AeadKey<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: AeadAlgorithm> Copy for AeadKey<A> {}

/// AEAD nonce with compile-time size.
pub struct Nonce<A: AeadAlgorithm> {
    bytes: [u8; MAX_AEAD_NONCE],
    _phantom: PhantomData<A>,
}

impl<A: AeadAlgorithm> Nonce<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::NONCE_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_AEAD_NONCE];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::NONCE_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_AEAD_NONCE];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_AEAD_NONCE],
            _phantom: PhantomData,
        }
    }
}

impl<A: AeadAlgorithm> Clone for Nonce<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: AeadAlgorithm> Copy for Nonce<A> {}

/// AEAD authentication tag with compile-time size.
pub struct Tag<A: AeadAlgorithm> {
    bytes: [u8; MAX_AEAD_TAG],
    _phantom: PhantomData<A>,
}

impl<A: AeadAlgorithm> Tag<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::TAG_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_AEAD_TAG];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::TAG_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::TAG_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_AEAD_TAG];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_AEAD_TAG],
            _phantom: PhantomData,
        }
    }
}

impl<A: AeadAlgorithm> Clone for Tag<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: AeadAlgorithm> Copy for Tag<A> {}

/// Hash output with compile-time algorithm binding.
pub struct HashOutput<A: HashAlgorithm> {
    bytes: [u8; MAX_HASH_OUT],
    _phantom: PhantomData<A>,
}

impl<A: HashAlgorithm> HashOutput<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::OUTPUT_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_HASH_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::OUTPUT_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::OUTPUT_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_HASH_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_HASH_OUT],
            _phantom: PhantomData,
        }
    }
}

impl<A: HashAlgorithm> Clone for HashOutput<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: HashAlgorithm> Copy for HashOutput<A> {}

/// HMAC output with compile-time algorithm binding.
pub struct HmacOutput<A: HmacAlgorithm> {
    bytes: [u8; MAX_HMAC_OUT],
    _phantom: PhantomData<A>,
}

impl<A: HmacAlgorithm> HmacOutput<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::OUTPUT_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_HMAC_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::OUTPUT_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::OUTPUT_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_HMAC_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_HMAC_OUT],
            _phantom: PhantomData,
        }
    }
}

impl<A: HmacAlgorithm> Clone for HmacOutput<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: HmacAlgorithm> Copy for HmacOutput<A> {}

/// DH public key with compile-time algorithm binding.
pub struct DhPublicKey<A: DhAlgorithm> {
    bytes: [u8; MAX_DH_PUBKEY],
    _phantom: PhantomData<A>,
}

impl<A: DhAlgorithm> DhPublicKey<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::PUBLIC_KEY_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_DH_PUBKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::PUBLIC_KEY_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::PUBLIC_KEY_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_DH_PUBKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_DH_PUBKEY],
            _phantom: PhantomData,
        }
    }
}

impl<A: DhAlgorithm> Clone for DhPublicKey<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: DhAlgorithm> Copy for DhPublicKey<A> {}

/// DH secret key with compile-time algorithm binding.
pub struct DhSecretKey<A: DhAlgorithm> {
    bytes: [u8; MAX_DH_SECKEY],
    _phantom: PhantomData<A>,
}

impl<A: DhAlgorithm> DhSecretKey<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::SECRET_KEY_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_DH_SECKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::SECRET_KEY_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::SECRET_KEY_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_DH_SECKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_DH_SECKEY],
            _phantom: PhantomData,
        }
    }
}

impl<A: DhAlgorithm> Clone for DhSecretKey<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: DhAlgorithm> Copy for DhSecretKey<A> {}

/// DH shared secret with compile-time algorithm binding.
pub struct DhSharedSecret<A: DhAlgorithm> {
    bytes: [u8; MAX_DH_SHARED],
    _phantom: PhantomData<A>,
}

impl<A: DhAlgorithm> DhSharedSecret<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::SHARED_SECRET_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_DH_SHARED];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::SHARED_SECRET_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::SHARED_SECRET_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_DH_SHARED];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_DH_SHARED],
            _phantom: PhantomData,
        }
    }
}

impl<A: DhAlgorithm> Clone for DhSharedSecret<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: DhAlgorithm> Copy for DhSharedSecret<A> {}

/// CORDIC input with compile-time algorithm binding.
pub struct CordicInput<A: CordicAlgorithm> {
    bytes: [u8; MAX_CORDIC_IN],
    _phantom: PhantomData<A>,
}

impl<A: CordicAlgorithm> CordicInput<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::INPUT_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_CORDIC_IN];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::INPUT_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::INPUT_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_CORDIC_IN];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_CORDIC_IN],
            _phantom: PhantomData,
        }
    }
}

impl<A: CordicAlgorithm> Clone for CordicInput<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: CordicAlgorithm> Copy for CordicInput<A> {}

/// CORDIC output with compile-time algorithm binding.
pub struct CordicOutput<A: CordicAlgorithm> {
    bytes: [u8; MAX_CORDIC_OUT],
    _phantom: PhantomData<A>,
}

impl<A: CordicAlgorithm> CordicOutput<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::OUTPUT_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_CORDIC_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::OUTPUT_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::OUTPUT_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_CORDIC_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_CORDIC_OUT],
            _phantom: PhantomData,
        }
    }
}

impl<A: CordicAlgorithm> Clone for CordicOutput<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: CordicAlgorithm> Copy for CordicOutput<A> {}

// ============================================================================
// Signature types
// ============================================================================

/// Signing key with compile-time algorithm binding.
pub struct SigningKey<A: SignAlgorithm> {
    bytes: [u8; MAX_SIGN_SECKEY],
    _phantom: PhantomData<A>,
}

impl<A: SignAlgorithm> SigningKey<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::SECRET_KEY_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_SIGN_SECKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::SECRET_KEY_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::SECRET_KEY_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_SIGN_SECKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_SIGN_SECKEY],
            _phantom: PhantomData,
        }
    }
}

impl<A: SignAlgorithm> Clone for SigningKey<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: SignAlgorithm> Copy for SigningKey<A> {}

/// Verifying key with compile-time algorithm binding.
pub struct VerifyingKey<A: VerifyAlgorithm> {
    bytes: [u8; MAX_SIGN_PUBKEY],
    _phantom: PhantomData<A>,
}

impl<A: VerifyAlgorithm> VerifyingKey<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::PUBLIC_KEY_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_SIGN_PUBKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::PUBLIC_KEY_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_SIGN_PUBKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_SIGN_PUBKEY],
            _phantom: PhantomData,
        }
    }
}

impl<A: VerifyAlgorithm> Clone for VerifyingKey<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: VerifyAlgorithm> Copy for VerifyingKey<A> {}

/// Signature with compile-time algorithm binding.
pub struct Signature<A: SignAlgorithm> {
    bytes: [u8; MAX_SIGN_SIG],
    _phantom: PhantomData<A>,
}

impl<A: SignAlgorithm> Signature<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::SIGNATURE_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_SIGN_SIG];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::SIGNATURE_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::SIGNATURE_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_SIGN_SIG];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_SIGN_SIG],
            _phantom: PhantomData,
        }
    }
}

impl<A: SignAlgorithm> Clone for Signature<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: SignAlgorithm> Copy for Signature<A> {}

// ============================================================================
// Cipher types
// ============================================================================

/// Cipher key with compile-time algorithm binding.
pub struct CipherKey<A: CipherAlgorithm> {
    bytes: [u8; MAX_CIPHER_KEY],
    _phantom: PhantomData<A>,
}

impl<A: CipherAlgorithm> CipherKey<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::KEY_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_CIPHER_KEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::KEY_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_CIPHER_KEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_CIPHER_KEY],
            _phantom: PhantomData,
        }
    }
}

impl<A: CipherAlgorithm> Clone for CipherKey<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: CipherAlgorithm> Copy for CipherKey<A> {}

/// Cipher IV with compile-time algorithm binding.
pub struct Iv<A: CipherAlgorithm> {
    bytes: [u8; MAX_CIPHER_IV],
    _phantom: PhantomData<A>,
}

impl<A: CipherAlgorithm> Iv<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::IV_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_CIPHER_IV];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::IV_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_CIPHER_IV];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_CIPHER_IV],
            _phantom: PhantomData,
        }
    }
}

impl<A: CipherAlgorithm> Clone for Iv<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: CipherAlgorithm> Copy for Iv<A> {}

// ============================================================================
// CRC types
// ============================================================================

/// CRC output with compile-time algorithm binding.
pub struct CrcOutput<A: CrcAlgorithm> {
    bytes: [u8; MAX_CRC_OUT],
    _phantom: PhantomData<A>,
}

impl<A: CrcAlgorithm> CrcOutput<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != A::OUTPUT_LEN {
            return Err(CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_CRC_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: arr,
            _phantom: PhantomData,
        })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::OUTPUT_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::OUTPUT_LEN]
    }
    #[allow(dead_code)]
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_CRC_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self {
            bytes: arr,
            _phantom: PhantomData,
        }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: [0u8; MAX_CRC_OUT],
            _phantom: PhantomData,
        }
    }
}

impl<A: CrcAlgorithm> Clone for CrcOutput<A> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes,
            _phantom: PhantomData,
        }
    }
}

impl<A: CrcAlgorithm> Copy for CrcOutput<A> {}
