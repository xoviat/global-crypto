//! Synchronous global crypto API.
//!
//! These functions are callable from anywhere without carrying around
//! a `&mut` reference to a crypto engine. The registry selects the best
//! available provider automatically.

use crate::driver::{
    CAP_AEAD, CAP_CIPHER, CAP_CORDIC, CAP_CRC, CAP_DH, CAP_HASH, CAP_HKDF, CAP_HMAC, CAP_SIGN,
    CAP_VERIFY,
};
use crate::registry::select_provider;
use crate::types::*;
use crate::CryptoError;

// ============================================================================
// AEAD
// ============================================================================

/// Encrypt a message in place using the globally-selected AEAD provider.
///
/// The authentication tag is written into `tag`.
#[inline]
pub fn aead_encrypt<A: AeadAlgorithm>(
    key: &AeadKey<A>,
    nonce: &Nonce<A>,
    message: &mut [u8],
    aad: &[u8],
    tag: &mut Tag<A>,
) -> Result<(), CryptoError> {
    let driver =
        select_provider(CAP_AEAD, |d| d.supports_aead(A::ID)).ok_or(CryptoError::NoProvider)?;

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
#[inline]
pub fn aead_decrypt<A: AeadAlgorithm>(
    key: &AeadKey<A>,
    nonce: &Nonce<A>,
    message: &mut [u8],
    tag: &Tag<A>,
    aad: &[u8],
) -> Result<(), CryptoError> {
    let driver =
        select_provider(CAP_AEAD, |d| d.supports_aead(A::ID)).ok_or(CryptoError::NoProvider)?;

    driver.aead_decrypt(
        A::ID,
        key.as_bytes(),
        nonce.as_bytes(),
        message,
        tag.as_bytes(),
        aad,
    )
}

// ============================================================================
// Hash (one-shot)
// ============================================================================

/// Hash `data` using the globally-selected hash provider.
#[inline]
pub fn hash<A: HashAlgorithm>(data: &[u8]) -> Result<HashOutput<A>, CryptoError> {
    let driver =
        select_provider(CAP_HASH, |d| d.supports_hash(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = HashOutput::<A>::zeroed();
    driver.hash(A::ID, data, out.as_bytes_mut())?;
    Ok(out)
}

// ============================================================================
// Hash (streaming)
// ============================================================================

/// Return the state buffer size required for the given hash algorithm.
#[inline]
pub fn hash_state_size<A: HashAlgorithm>() -> usize {
    match select_provider(CAP_HASH, |d| d.supports_hash(A::ID)) {
        Some(driver) => driver.hash_state_size(A::ID),
        None => 0,
    }
}

/// Initialize a streaming hash context.
///
/// `state` must be at least `hash_state_size::<A>()` bytes.
#[inline]
pub fn hash_init<A: HashAlgorithm>(state: &mut [u8]) -> Result<(), CryptoError> {
    let driver =
        select_provider(CAP_HASH, |d| d.supports_hash(A::ID)).ok_or(CryptoError::NoProvider)?;
    driver.hash_init(A::ID, state)
}

/// Update a streaming hash context with more data.
///
/// # Note
/// This selects the highest-priority hash provider. In multi-provider
/// setups where different hash algorithms use different providers, the
/// caller must ensure only one hash provider is registered.
#[inline]
pub fn hash_update(state: &mut [u8], data: &[u8]) -> Result<(), CryptoError> {
    let driver = select_provider(CAP_HASH, |_| true).ok_or(CryptoError::NoProvider)?;
    driver.hash_update(state, data)
}

/// Finalize a streaming hash context and write the digest.
#[inline]
pub fn hash_finalize<A: HashAlgorithm>(
    state: &mut [u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let driver =
        select_provider(CAP_HASH, |d| d.supports_hash(A::ID)).ok_or(CryptoError::NoProvider)?;
    driver.hash_finalize(state, out)
}

// ============================================================================
// HMAC
// ============================================================================

/// Compute HMAC over `data` using the globally-selected HMAC provider.
#[inline]
pub fn hmac<A: HmacAlgorithm>(key: &[u8], data: &[u8]) -> Result<HmacOutput<A>, CryptoError> {
    let driver =
        select_provider(CAP_HMAC, |d| d.supports_hmac(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = HmacOutput::<A>::zeroed();
    driver.hmac(A::ID, key, data, out.as_bytes_mut())?;
    Ok(out)
}

// ============================================================================
// Diffie-Hellman
// ============================================================================

/// Generate a new DH keypair using the globally-selected DH provider.
#[inline]
pub fn dh_generate_keypair<A: DhAlgorithm>() -> Result<(DhPublicKey<A>, DhSecretKey<A>), CryptoError>
{
    let driver =
        select_provider(CAP_DH, |d| d.supports_dh(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut pubkey = DhPublicKey::<A>::zeroed();
    let mut seckey = DhSecretKey::<A>::zeroed();
    driver.dh_generate_keypair(A::ID, pubkey.as_bytes_mut(), seckey.as_bytes_mut())?;
    Ok((pubkey, seckey))
}

/// Derive a shared secret using the globally-selected DH provider.
#[inline]
pub fn dh_shared_secret<A: DhAlgorithm>(
    seckey: &DhSecretKey<A>,
    pubkey: &DhPublicKey<A>,
) -> Result<DhSharedSecret<A>, CryptoError> {
    let driver =
        select_provider(CAP_DH, |d| d.supports_dh(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = DhSharedSecret::<A>::zeroed();
    driver.dh_shared_secret(
        A::ID,
        seckey.as_bytes(),
        pubkey.as_bytes(),
        out.as_bytes_mut(),
    )?;
    Ok(out)
}

// ============================================================================
// HKDF
// ============================================================================

/// HKDF-Extract using the globally-selected provider.
#[inline]
pub fn hkdf_extract<A: HmacAlgorithm>(
    salt: Option<&[u8]>,
    ikm: &[u8],
) -> Result<HmacOutput<A>, CryptoError> {
    let driver =
        select_provider(CAP_HKDF, |d| d.supports_hkdf(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = HmacOutput::<A>::zeroed();
    driver.hkdf_extract(A::ID, salt, ikm, out.as_bytes_mut())?;
    Ok(out)
}

/// HKDF-Expand using the globally-selected provider.
#[inline]
pub fn hkdf_expand<A: HmacAlgorithm>(
    prk: &HmacOutput<A>,
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), CryptoError> {
    let driver =
        select_provider(CAP_HKDF, |d| d.supports_hkdf(A::ID)).ok_or(CryptoError::NoProvider)?;

    driver.hkdf_expand(A::ID, prk.as_bytes(), info, okm)
}

// ============================================================================
// CORDIC
// ============================================================================

/// Execute a CORDIC computation using the globally-selected provider.
#[inline]
pub fn cordic_compute<A: CordicAlgorithm>(
    input: &CordicInput<A>,
) -> Result<CordicOutput<A>, CryptoError> {
    let driver =
        select_provider(CAP_CORDIC, |d| d.supports_cordic(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = CordicOutput::<A>::zeroed();
    driver.cordic_compute(A::ID, input.as_bytes(), out.as_bytes_mut())?;
    Ok(out)
}

// ============================================================================
// Digital signatures
// ============================================================================

/// Sign `message` using the globally-selected signing provider.
#[inline]
pub fn sign<A: SignAlgorithm>(
    seckey: &SigningKey<A>,
    message: &[u8],
) -> Result<Signature<A>, CryptoError> {
    let driver =
        select_provider(CAP_SIGN, |d| d.supports_sign(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = Signature::<A>::zeroed();
    driver.sign(A::ID, seckey.as_bytes(), message, out.as_bytes_mut())?;
    Ok(out)
}

/// Verify `signature` over `message` using the globally-selected verification provider.
#[inline]
pub fn verify<A: VerifyAlgorithm + SignAlgorithm>(
    pubkey: &VerifyingKey<A>,
    message: &[u8],
    signature: &Signature<A>,
) -> Result<(), CryptoError> {
    let driver = select_provider(CAP_VERIFY, |d| {
        d.supports_verify(<A as VerifyAlgorithm>::ID)
    })
    .ok_or(CryptoError::NoProvider)?;

    driver.verify(
        <A as VerifyAlgorithm>::ID,
        pubkey.as_bytes(),
        message,
        signature.as_bytes(),
    )
}

// ============================================================================
// Raw symmetric cipher
// ============================================================================

/// Encrypt `data` in place using the globally-selected cipher provider.
#[inline]
pub fn cipher_encrypt<A: CipherAlgorithm>(
    key: &CipherKey<A>,
    iv: &Iv<A>,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let driver =
        select_provider(CAP_CIPHER, |d| d.supports_cipher(A::ID)).ok_or(CryptoError::NoProvider)?;

    driver.cipher_encrypt(A::ID, key.as_bytes(), iv.as_bytes(), data)
}

/// Decrypt `data` in place using the globally-selected cipher provider.
#[inline]
pub fn cipher_decrypt<A: CipherAlgorithm>(
    key: &CipherKey<A>,
    iv: &Iv<A>,
    data: &mut [u8],
) -> Result<(), CryptoError> {
    let driver =
        select_provider(CAP_CIPHER, |d| d.supports_cipher(A::ID)).ok_or(CryptoError::NoProvider)?;

    driver.cipher_decrypt(A::ID, key.as_bytes(), iv.as_bytes(), data)
}

// ============================================================================
// CRC
// ============================================================================

/// Compute CRC over `data` using the globally-selected CRC provider.
#[inline]
pub fn crc_compute<A: CrcAlgorithm>(data: &[u8]) -> Result<CrcOutput<A>, CryptoError> {
    let driver =
        select_provider(CAP_CRC, |d| d.supports_crc(A::ID)).ok_or(CryptoError::NoProvider)?;

    let mut out = CrcOutput::<A>::zeroed();
    driver.crc_compute(A::ID, data, out.as_bytes_mut())?;
    Ok(out)
}
