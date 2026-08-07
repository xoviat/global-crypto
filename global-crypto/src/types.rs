//! Rich algorithm and data types.
//!
//! These types live *above* the `dyn CryptoDriver` boundary.
//! They provide algorithm-tagging to prevent mixing keys across algorithms.
//!
//! Note: Stable Rust does not allow generic parameters in const array sizes
//! (`[u8; A::KEY_LEN]`). We use max-size backing arrays + PhantomData instead.
//! The `as_bytes()` method returns a correctly-sized slice.

use core::marker::PhantomData;

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
pub(crate) const MAX_HMAC_KEY: usize = 128;
pub(crate) const MAX_HMAC_OUT: usize = 64;
pub(crate) const MAX_DH_PUBKEY: usize = 49;
pub(crate) const MAX_DH_SECKEY: usize = 48;
pub(crate) const MAX_DH_SHARED: usize = 48;
pub(crate) const MAX_CORDIC_IN: usize = 16;
pub(crate) const MAX_CORDIC_OUT: usize = 16;

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
}

/// CORDIC algorithm identifier for the object-safe driver boundary.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CordicAlgorithmId {
    SinCos,
    Atan2,
    Hypot,
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

/// ECDH on P-256 (COSE curve 1).
#[derive(Clone, Copy)]
pub struct EcdhP256;
impl sealed::Sealed for EcdhP256 {}
impl DhAlgorithm for EcdhP256 {
    const SECRET_KEY_LEN: usize = 32;
    const PUBLIC_KEY_LEN: usize = 33; // compressed
    const SHARED_SECRET_LEN: usize = 32;
    const ID: DhAlgorithmId = DhAlgorithmId::EcdhP256;
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

// ============================================================================
// Rich data types (algorithm-parameterised, max-size backing arrays)
// ============================================================================

/// AEAD key with compile-time algorithm binding.
pub struct AeadKey<A: AeadAlgorithm> {
    bytes: [u8; MAX_AEAD_KEY],
    _phantom: PhantomData<A>,
}

impl<A: AeadAlgorithm> AeadKey<A> {
    /// Import a key from raw bytes. Validates length against `A::KEY_LEN`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoError> {
        if bytes.len() != A::KEY_LEN {
            return Err(crate::CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_AEAD_KEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: arr, _phantom: PhantomData })
    }
    /// Access the raw key bytes (correctly sized slice).
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::KEY_LEN]
    }
    /// Internal constructor that copies exactly `A::KEY_LEN` bytes.
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_AEAD_KEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: arr, _phantom: PhantomData }
    }
    /// Return a zeroed key (for driver output).
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self { bytes: [0u8; MAX_AEAD_KEY], _phantom: PhantomData }
    }
}

impl<A: AeadAlgorithm> Clone for AeadKey<A> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes, _phantom: PhantomData }
    }
}

impl<A: AeadAlgorithm> Copy for AeadKey<A> {}

/// AEAD nonce with compile-time size.
pub struct Nonce<A: AeadAlgorithm> {
    bytes: [u8; MAX_AEAD_NONCE],
    _phantom: PhantomData<A>,
}

impl<A: AeadAlgorithm> Nonce<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoError> {
        if bytes.len() != A::NONCE_LEN {
            return Err(crate::CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_AEAD_NONCE];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: arr, _phantom: PhantomData })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::NONCE_LEN]
    }
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_AEAD_NONCE];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: arr, _phantom: PhantomData }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self { bytes: [0u8; MAX_AEAD_NONCE], _phantom: PhantomData }
    }
}

impl<A: AeadAlgorithm> Clone for Nonce<A> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes, _phantom: PhantomData }
    }
}

impl<A: AeadAlgorithm> Copy for Nonce<A> {}

/// AEAD authentication tag with compile-time size.
pub struct Tag<A: AeadAlgorithm> {
    bytes: [u8; MAX_AEAD_TAG],
    _phantom: PhantomData<A>,
}

impl<A: AeadAlgorithm> Tag<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoError> {
        if bytes.len() != A::TAG_LEN {
            return Err(crate::CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_AEAD_TAG];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: arr, _phantom: PhantomData })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::TAG_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::TAG_LEN]
    }
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_AEAD_TAG];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: arr, _phantom: PhantomData }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self { bytes: [0u8; MAX_AEAD_TAG], _phantom: PhantomData }
    }
}

impl<A: AeadAlgorithm> Clone for Tag<A> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes, _phantom: PhantomData }
    }
}

impl<A: AeadAlgorithm> Copy for Tag<A> {}

/// Hash output with compile-time algorithm binding.
pub struct HashOutput<A: HashAlgorithm> {
    bytes: [u8; MAX_HASH_OUT],
    _phantom: PhantomData<A>,
}

impl<A: HashAlgorithm> HashOutput<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoError> {
        if bytes.len() != A::OUTPUT_LEN {
            return Err(crate::CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_HASH_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: arr, _phantom: PhantomData })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::OUTPUT_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::OUTPUT_LEN]
    }
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_HASH_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: arr, _phantom: PhantomData }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self { bytes: [0u8; MAX_HASH_OUT], _phantom: PhantomData }
    }
}

impl<A: HashAlgorithm> Clone for HashOutput<A> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes, _phantom: PhantomData }
    }
}

impl<A: HashAlgorithm> Copy for HashOutput<A> {}

/// HMAC output with compile-time algorithm binding.
pub struct HmacOutput<A: HmacAlgorithm> {
    bytes: [u8; MAX_HMAC_OUT],
    _phantom: PhantomData<A>,
}

impl<A: HmacAlgorithm> HmacOutput<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoError> {
        if bytes.len() != A::OUTPUT_LEN {
            return Err(crate::CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_HMAC_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: arr, _phantom: PhantomData })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::OUTPUT_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::OUTPUT_LEN]
    }
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_HMAC_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: arr, _phantom: PhantomData }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self { bytes: [0u8; MAX_HMAC_OUT], _phantom: PhantomData }
    }
}

impl<A: HmacAlgorithm> Clone for HmacOutput<A> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes, _phantom: PhantomData }
    }
}

impl<A: HmacAlgorithm> Copy for HmacOutput<A> {}

/// DH public key with compile-time algorithm binding.
pub struct DhPublicKey<A: DhAlgorithm> {
    bytes: [u8; MAX_DH_PUBKEY],
    _phantom: PhantomData<A>,
}

impl<A: DhAlgorithm> DhPublicKey<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoError> {
        if bytes.len() != A::PUBLIC_KEY_LEN {
            return Err(crate::CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_DH_PUBKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: arr, _phantom: PhantomData })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::PUBLIC_KEY_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::PUBLIC_KEY_LEN]
    }
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_DH_PUBKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: arr, _phantom: PhantomData }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self { bytes: [0u8; MAX_DH_PUBKEY], _phantom: PhantomData }
    }
}

impl<A: DhAlgorithm> Clone for DhPublicKey<A> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes, _phantom: PhantomData }
    }
}

impl<A: DhAlgorithm> Copy for DhPublicKey<A> {}

/// DH secret key with compile-time algorithm binding.
pub struct DhSecretKey<A: DhAlgorithm> {
    bytes: [u8; MAX_DH_SECKEY],
    _phantom: PhantomData<A>,
}

impl<A: DhAlgorithm> DhSecretKey<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoError> {
        if bytes.len() != A::SECRET_KEY_LEN {
            return Err(crate::CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_DH_SECKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: arr, _phantom: PhantomData })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::SECRET_KEY_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::SECRET_KEY_LEN]
    }
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_DH_SECKEY];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: arr, _phantom: PhantomData }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self { bytes: [0u8; MAX_DH_SECKEY], _phantom: PhantomData }
    }
}

impl<A: DhAlgorithm> Clone for DhSecretKey<A> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes, _phantom: PhantomData }
    }
}

impl<A: DhAlgorithm> Copy for DhSecretKey<A> {}

/// DH shared secret with compile-time algorithm binding.
pub struct DhSharedSecret<A: DhAlgorithm> {
    bytes: [u8; MAX_DH_SHARED],
    _phantom: PhantomData<A>,
}

impl<A: DhAlgorithm> DhSharedSecret<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoError> {
        if bytes.len() != A::SHARED_SECRET_LEN {
            return Err(crate::CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_DH_SHARED];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: arr, _phantom: PhantomData })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::SHARED_SECRET_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::SHARED_SECRET_LEN]
    }
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_DH_SHARED];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: arr, _phantom: PhantomData }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self { bytes: [0u8; MAX_DH_SHARED], _phantom: PhantomData }
    }
}

impl<A: DhAlgorithm> Clone for DhSharedSecret<A> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes, _phantom: PhantomData }
    }
}

impl<A: DhAlgorithm> Copy for DhSharedSecret<A> {}

/// CORDIC input with compile-time algorithm binding.
pub struct CordicInput<A: CordicAlgorithm> {
    bytes: [u8; MAX_CORDIC_IN],
    _phantom: PhantomData<A>,
}

impl<A: CordicAlgorithm> CordicInput<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoError> {
        if bytes.len() != A::INPUT_LEN {
            return Err(crate::CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_CORDIC_IN];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: arr, _phantom: PhantomData })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::INPUT_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::INPUT_LEN]
    }
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_CORDIC_IN];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: arr, _phantom: PhantomData }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self { bytes: [0u8; MAX_CORDIC_IN], _phantom: PhantomData }
    }
}

impl<A: CordicAlgorithm> Clone for CordicInput<A> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes, _phantom: PhantomData }
    }
}

impl<A: CordicAlgorithm> Copy for CordicInput<A> {}

/// CORDIC output with compile-time algorithm binding.
pub struct CordicOutput<A: CordicAlgorithm> {
    bytes: [u8; MAX_CORDIC_OUT],
    _phantom: PhantomData<A>,
}

impl<A: CordicAlgorithm> CordicOutput<A> {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::CryptoError> {
        if bytes.len() != A::OUTPUT_LEN {
            return Err(crate::CryptoError::BufferTooSmall);
        }
        let mut arr = [0u8; MAX_CORDIC_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: arr, _phantom: PhantomData })
    }
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..A::OUTPUT_LEN]
    }
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..A::OUTPUT_LEN]
    }
    pub(crate) fn from_slice_unchecked(bytes: &[u8]) -> Self {
        let mut arr = [0u8; MAX_CORDIC_OUT];
        arr[..bytes.len()].copy_from_slice(bytes);
        Self { bytes: arr, _phantom: PhantomData }
    }
    #[inline]
    pub(crate) fn zeroed() -> Self {
        Self { bytes: [0u8; MAX_CORDIC_OUT], _phantom: PhantomData }
    }
}

impl<A: CordicAlgorithm> Clone for CordicOutput<A> {
    fn clone(&self) -> Self {
        Self { bytes: self.bytes, _phantom: PhantomData }
    }
}

impl<A: CordicAlgorithm> Copy for CordicOutput<A> {}
