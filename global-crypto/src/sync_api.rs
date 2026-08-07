//! Synchronous global crypto API.
//!
//! These functions are callable from anywhere without carrying around
//! a `&mut` reference to a crypto engine. The registry selects the best
//! available provider automatically.

use crate::{registry::select_provider, types::*, CryptoError};

// ============================================================================
// AEAD
// ============================================================================

/// Encrypt a message in place using the globally-selected AEAD provider.
///
/// The authentication tag is written into `tag`.
pub fn aead_encrypt<A: AeadAlgorithm>(
    key: &AeadKey<A>,
    nonce: &Nonce<A>,
    message: &mut [u8],
    aad: &[u8],
    tag: &mut Tag<A>,
) -> Result<(), CryptoError> {
    let driver = select_provider(|d| d.supports_aead(A::ID)).ok_or(CryptoError::NoProvider)?;

    driver.aead_encrypt(
        A::ID,
        key.as_bytes(),
        nonce.as_bytes(),
        message,
        aad,
        tag.as_bytes_mut(),
    )
}

/// Decrypt a message in place using the globally-selected AEAD provider.
///
/// Returns `DecryptionFailed` if the tag does not verify.
pub fn aead_decrypt<A: AeadAlgorithm>(
    key: &AeadKey<A>,
    nonce: &Nonce<A>,
    message: &mut [u8],
    tag: &mut Tag<A>,
    aad: &[u8],
) -> Result<(), CryptoError> {
    let driver = select_provider(|d| d.supports_aead(A::ID)).ok_or(CryptoError::NoProvider)?;

    driver.aead_decrypt(
        A::ID,
        key.as_bytes(),
        nonce.as_bytes(),
        message,
        tag.as_bytes_mut(),
        aad,
    )
}

// ============================================================================
// Hash
// ============================================================================

/// Hash `data` using the globally-selected hash provider.
pub fn hash<A: HashAlgorithm>(data: &[u8]) -> Result<HashOutput<A>, CryptoError> {
    let driver = select_provider(|d| d.supports_hash(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = [0u8; MAX_HASH_OUT];
    driver.hash(A::ID, data, &mut out[..A::OUTPUT_LEN])?;
    Ok(HashOutput::from_slice_unchecked(&out[..A::OUTPUT_LEN]))
}

// ============================================================================
// HMAC
// ============================================================================

/// Compute HMAC over `data` using the globally-selected HMAC provider.
pub fn hmac<A: HmacAlgorithm>(key: &[u8], data: &[u8]) -> Result<HmacOutput<A>, CryptoError> {
    let driver = select_provider(|d| d.supports_hmac(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = [0u8; MAX_HMAC_OUT];
    driver.hmac(A::ID, key, data, &mut out[..A::OUTPUT_LEN])?;
    Ok(HmacOutput::from_slice_unchecked(&out[..A::OUTPUT_LEN]))
}

// ============================================================================
// Diffie-Hellman
// ============================================================================

/// Generate a new DH keypair using the globally-selected DH provider.
pub fn dh_generate_keypair<A: DhAlgorithm>() -> Result<(DhPublicKey<A>, DhSecretKey<A>), CryptoError>
{
    let driver = select_provider(|d| d.supports_dh(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut pubkey = [0u8; MAX_DH_PUBKEY];
    let mut seckey = [0u8; MAX_DH_SECKEY];
    driver.dh_generate_keypair(
        A::ID,
        &mut pubkey[..A::PUBLIC_KEY_LEN],
        &mut seckey[..A::SECRET_KEY_LEN],
    )?;
    Ok((
        DhPublicKey::from_slice_unchecked(&pubkey[..A::PUBLIC_KEY_LEN]),
        DhSecretKey::from_slice_unchecked(&seckey[..A::SECRET_KEY_LEN]),
    ))
}

/// Derive a shared secret using the globally-selected DH provider.
pub fn dh_shared_secret<A: DhAlgorithm>(
    seckey: &DhSecretKey<A>,
    pubkey: &DhPublicKey<A>,
) -> Result<DhSharedSecret<A>, CryptoError> {
    let driver = select_provider(|d| d.supports_dh(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = [0u8; MAX_DH_SHARED];
    driver.dh_shared_secret(
        A::ID,
        seckey.as_bytes(),
        pubkey.as_bytes(),
        &mut out[..A::SHARED_SECRET_LEN],
    )?;
    Ok(DhSharedSecret::from_slice_unchecked(
        &out[..A::SHARED_SECRET_LEN],
    ))
}

// ============================================================================
// HKDF
// ============================================================================

/// HKDF-Extract using the globally-selected provider.
pub fn hkdf_extract<A: HmacAlgorithm>(
    salt: Option<&[u8]>,
    ikm: &[u8],
) -> Result<HmacOutput<A>, CryptoError> {
    let driver = select_provider(|d| d.supports_hkdf(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = [0u8; MAX_HMAC_OUT];
    driver.hkdf_extract(A::ID, salt, ikm, &mut out[..A::OUTPUT_LEN])?;
    Ok(HmacOutput::from_slice_unchecked(&out[..A::OUTPUT_LEN]))
}

/// HKDF-Expand using the globally-selected provider.
pub fn hkdf_expand<A: HmacAlgorithm>(
    prk: &HmacOutput<A>,
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    let driver = select_provider(|d| d.supports_hkdf(A::ID)).ok_or(CryptoError::NoProvider)?;

    driver.hkdf_expand(A::ID, prk.as_bytes(), info, okm)
}
