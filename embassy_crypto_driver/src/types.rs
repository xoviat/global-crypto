#![allow(dead_code)]

/// Capability flags reported by a driver.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
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

/// Errors returned by crypto operations.
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
