//! Object-safe cryptographic driver trait.
//!
//! This is the boundary between the rich global API and provider-specific
//! implementations. All methods take `&self` and use interior mutability
//! where needed (e.g. hardware register access).

use crate::{AeadAlgorithmId, HashAlgorithmId, HmacAlgorithmId, DhAlgorithmId, CryptoError};

/// Dyn-safe cryptographic driver trait.
///
/// Implement this trait for each crypto backend (software, hardware accelerator,
/// embedded-cal bridge, etc.). The trait is designed to be object-safe so it
/// can be used as `dyn CryptoDriver` in the global registry.
pub trait CryptoDriver: Send + Sync {
    // ------------------------------------------------------------------
    // Capability queries
    // ------------------------------------------------------------------

    /// Returns `true` if this provider supports the given AEAD algorithm.
    fn supports_aead(&self, _alg: AeadAlgorithmId) -> bool {
        false
    }

    /// Returns `true` if this provider supports the given hash algorithm.
    fn supports_hash(&self, _alg: HashAlgorithmId) -> bool {
        false
    }

    /// Returns `true` if this provider supports the given HMAC algorithm.
    fn supports_hmac(&self, _alg: HmacAlgorithmId) -> bool {
        false
    }

    /// Returns `true` if this provider supports the given DH algorithm.
    fn supports_dh(&self, _alg: DhAlgorithmId) -> bool {
        false
    }

    /// Returns `true` if this provider supports HKDF with the given HMAC algorithm.
    fn supports_hkdf(&self, _alg: HmacAlgorithmId) -> bool {
        false
    }

    // ------------------------------------------------------------------
    // AEAD
    // ------------------------------------------------------------------

    /// Encrypt `message` in place and write the authentication tag into `tag_out`.
    ///
    /// # Errors
    /// - `UnsupportedAlgorithm` if the algorithm is not supported.
    /// - `BufferTooSmall` if `tag_out` is not the correct size for the algorithm.
    fn aead_encrypt(
        &self,
        _alg: AeadAlgorithmId,
        _key: &[u8],
        _nonce: &[u8],
        _message: &mut [u8],
        _aad: &[u8],
        _tag_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }

    /// Decrypt `message` in place and verify the authentication tag.
    ///
    /// # Errors
    /// - `DecryptionFailed` if the tag does not match.
    /// - `UnsupportedAlgorithm` if the algorithm is not supported.
    fn aead_decrypt(
        &self,
        _alg: AeadAlgorithmId,
        _key: &[u8],
        _nonce: &[u8],
        _message: &mut [u8],
        _tag: &[u8],
        _aad: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }

    // ------------------------------------------------------------------
    // Hash
    // ------------------------------------------------------------------

    /// Hash `data` and write the digest into `out`.
    ///
    /// # Errors
    /// - `BufferTooSmall` if `out` is not the correct size for the algorithm.
    fn hash(
        &self,
        _alg: HashAlgorithmId,
        _data: &[u8],
        _out: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }

    // ------------------------------------------------------------------
    // HMAC
    // ------------------------------------------------------------------

    /// Compute HMAC over `data` with `key` and write the result into `out`.
    ///
    /// # Errors
    /// - `BufferTooSmall` if `out` is not the correct size for the algorithm.
    fn hmac(
        &self,
        _alg: HmacAlgorithmId,
        _key: &[u8],
        _data: &[u8],
        _out: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }

    // ------------------------------------------------------------------
    // Diffie-Hellman
    // ------------------------------------------------------------------

    /// Generate a new DH keypair.
    ///
    /// # Errors
    /// - `BufferTooSmall` if output buffers are not the correct sizes.
    fn dh_generate_keypair(
        &self,
        _alg: DhAlgorithmId,
        _pubkey_out: &mut [u8],
        _seckey_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }

    /// Derive a shared secret from a secret key and a peer's public key.
    ///
    /// # Errors
    /// - `BufferTooSmall` if `out` is not the correct size.
    /// - `ImportError` if the key bytes are malformed.
    /// - `IncompatibleKeys` if the keys belong to different algorithms.
    fn dh_shared_secret(
        &self,
        _alg: DhAlgorithmId,
        _seckey: &[u8],
        _pubkey: &[u8],
        _out: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }

    // ------------------------------------------------------------------
    // HKDF
    // ------------------------------------------------------------------

    /// HKDF-Extract (RFC 5869).
    ///
    /// # Errors
    /// - `BufferTooSmall` if `out` is not the correct size for the hash algorithm.
    fn hkdf_extract(
        &self,
        _alg: HmacAlgorithmId,
        _salt: Option<&[u8]>,
        _ikm: &[u8],
        _out: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }

    /// HKDF-Expand (RFC 5869).
    ///
    /// # Errors
    /// - `BufferTooSmall` if `okm` is too long for the algorithm (> 255 * hash_len).
    fn hkdf_expand(
        &self,
        _alg: HmacAlgorithmId,
        _prk: &[u8],
        _info: &[u8],
        _okm: &mut [u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedAlgorithm)
    }
}
