#![allow(dead_code)]

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Capabilities(pub u32);

impl Capabilities {
    pub const AES_128_ECB: Self = Self(1 << 0);
    pub const AES_128_CMAC: Self = Self(1 << 1);
    pub const AES_128_GCM: Self = Self(1 << 2);
    pub const AES_256_GCM: Self = Self(1 << 3);
    pub const AES_128_CCM: Self = Self(1 << 4);
    pub const AES_128_CCM8: Self = Self(1 << 5);
    pub const SHA_256: Self = Self(1 << 6);
    pub const SHA_384: Self = Self(1 << 7);
    pub const P256_ECDH: Self = Self(1 << 8);
    pub const P256_ECDSA_SIGN: Self = Self(1 << 9);
    pub const P256_ECDSA_VERIFY: Self = Self(1 << 10);
    pub const P256_KEYGEN: Self = Self(1 << 11);
    pub const P384_ECDH: Self = Self(1 << 12);
    pub const P384_ECDSA_SIGN: Self = Self(1 << 13);
    pub const P384_ECDSA_VERIFY: Self = Self(1 << 14);
    pub const P384_KEYGEN: Self = Self(1 << 15);
    pub const RSA_PKCS1V15_SHA256: Self = Self(1 << 16);
    pub const RSA_PKCS1V15_SHA384: Self = Self(1 << 17);
    pub const RSA_PKCS1V15_SHA512: Self = Self(1 << 18);
    pub const RSA_PSS_SHA256: Self = Self(1 << 19);
    pub const RSA_PSS_SHA384: Self = Self(1 << 20);
    pub const RSA_PSS_SHA512: Self = Self(1 << 21);
    pub const RNG: Self = Self(1 << 22);
    pub const SHA_1: Self = Self(1 << 23);
    pub const MD5: Self = Self(1 << 24);
    pub const SHA_224: Self = Self(1 << 25);
    pub const SHA_512_224: Self = Self(1 << 26);
    pub const SHA_512_256: Self = Self(1 << 27);
    pub const SHA_512: Self = Self(1 << 28);
    pub const HMAC_SHA256: Self = Self(1 << 29);
    pub const HMAC_SHA384: Self = Self(1 << 30);
    pub const HMAC_SHA512: Self = Self(1 << 31);

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn all() -> Self {
        Self(u32::MAX)
    }
}

impl core::ops::BitOr for Capabilities {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Capabilities {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    Unsupported,
    InvalidKey,
    InvalidInput,
    InvalidSignature,
    BufferTooSmall,
    HardwareError,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "unsupported operation"),
            Self::InvalidKey => write!(f, "invalid key"),
            Self::InvalidInput => write!(f, "invalid input"),
            Self::InvalidSignature => write!(f, "invalid signature / tag"),
            Self::BufferTooSmall => write!(f, "buffer too small"),
            Self::HardwareError => write!(f, "hardware error"),
        }
    }
}

/// Hash algorithm selection for streaming operations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algorithm {
    /// SHA-1 Algorithm
    SHA1 = 0,

    /// MD5 Algorithm
    MD5 = 1,

    /// SHA-224 Algorithm
    SHA224 = 2,

    /// SHA-256 Algorithm
    SHA256 = 3,

    /// SHA-384 Algorithm
    SHA384 = 12,

    /// SHA-512/224 Algorithm
    SHA512_224 = 13,

    /// SHA-512/256 Algorithm
    SHA512_256 = 14,

    /// SHA-512 Algorithm
    SHA512 = 15,
    /// HMAC-SHA-256 Algorithm
    HmacSha256 = 16,
    /// HMAC-SHA-384 Algorithm
    HmacSha384 = 17,
    /// HMAC-SHA-512 Algorithm
    HmacSha512 = 18,
}

impl Algorithm {
    pub const fn required_caps(&self) -> Capabilities {
        match self {
            Self::SHA1 => Capabilities::SHA_1,
            Self::MD5 => Capabilities::MD5,
            Self::SHA224 => Capabilities::SHA_224,
            Self::SHA256 => Capabilities::SHA_256,
            Self::SHA384 => Capabilities::SHA_384,
            Self::SHA512_224 => Capabilities::SHA_512_224,
            Self::SHA512_256 => Capabilities::SHA_512_256,
            Self::SHA512 => Capabilities::SHA_512,
            Self::HmacSha256 => Capabilities::HMAC_SHA256,
            Self::HmacSha384 => Capabilities::HMAC_SHA384,
            Self::HmacSha512 => Capabilities::HMAC_SHA512,
        }
    }

    pub const fn digest_len(&self) -> usize {
        match self {
            Self::SHA1 => 20,
            Self::MD5 => 16,
            Self::SHA224 => 28,
            Self::SHA256 => 32,
            Self::SHA384 => 48,
            Self::SHA512_224 => 28,
            Self::SHA512_256 => 32,
            Self::SHA512 => 64,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
        }
    }
}

/// Opaque context buffer for streaming hash operations.
///
/// Drivers interpret the contents; the framework only stores and retrieves it.
/// The size (128 bytes) is large enough for common software and hardware
/// SHA-256 and hardware SHA-384 contexts.
#[derive(Clone, Copy)]
pub struct HashContext(pub [u8; 128]);

impl Default for HashContext {
    fn default() -> Self {
        Self([0u8; 128])
    }
}
