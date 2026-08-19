#![cfg_attr(not(test), no_std)]

pub mod traits;
pub mod types;

pub use traits::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_empty() {
        let c = Capabilities(0);
        assert!(c.is_empty());
        assert!(!c.contains(Capabilities::AES_128_GCM));
    }

    #[test]
    fn capabilities_single() {
        let c = Capabilities::SHA_256;
        assert!(c.contains(Capabilities::SHA_256));
        assert!(!c.contains(Capabilities::SHA_384));
    }

    #[test]
    fn capabilities_bitor() {
        let c = Capabilities::AES_128_GCM | Capabilities::SHA_256 | Capabilities::RNG;
        assert!(c.contains(Capabilities::AES_128_GCM));
        assert!(c.contains(Capabilities::SHA_256));
        assert!(c.contains(Capabilities::RNG));
        assert!(!c.contains(Capabilities::AES_256_GCM));
    }

    #[test]
    fn capabilities_bitor_assign() {
        let mut c = Capabilities::AES_128_GCM;
        c |= Capabilities::SHA_256;
        assert!(c.contains(Capabilities::AES_128_GCM));
        assert!(c.contains(Capabilities::SHA_256));
    }

    #[test]
    fn crypto_error_display() {
        let e = CryptoError::InvalidSignature;
        assert_eq!(format!("{e}"), "invalid signature / tag");
    }
}
