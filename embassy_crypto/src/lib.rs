#![no_std]

pub use embassy_crypto_driver::{
    Algorithm, BlockingOp, ContextHandle, CryptoError, HashContext,
};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use ccm::aead::AeadInPlace as CcmAeadInPlace;
use ccm::{consts::U13, consts::U8 as Tag8, consts::U16 as Tag16, Ccm};
use cmac::Cmac;
use digest::Mac;
use generic_array::GenericArray;

// Type aliases for CCM modes (13-byte nonce, 802.15.4 style)
type Ccm128 = Ccm<Aes128, Tag16, U13>;
type Ccm8_128 = Ccm<Aes128, Tag8, U13>;

// ------------------------------------------------------------------
// Blocking dispatch
// ------------------------------------------------------------------

/// Dispatch a blocking operation, trying the linked driver first and
/// falling back to a software implementation on `Unsupported` or `None`.
pub fn dispatch_blocking(op: BlockingOp<'_>) -> Result<(), CryptoError> {
    match op {
        BlockingOp::Aes128EcbEncrypt { block, key } => aes_128_ecb_encrypt(block, key),
        BlockingOp::Aes128EcbDecrypt { block, key } => aes_128_ecb_decrypt(block, key),
        BlockingOp::Aes128Cmac { key, data, out } => aes_128_cmac(key, data, out),
        BlockingOp::AesCcm128Encrypt { key, nonce, aad, plaintext, ciphertext, tag } => {
            aes_ccm_128_encrypt(key, nonce, aad, plaintext, ciphertext, tag)
        }
        BlockingOp::AesCcm128Decrypt { key, nonce, aad, ciphertext, plaintext, tag } => {
            aes_ccm_128_decrypt(key, nonce, aad, ciphertext, plaintext, tag)
        }
        BlockingOp::AesCcm8_128Encrypt { key, nonce, aad, plaintext, ciphertext, tag } => {
            aes_ccm8_128_encrypt(key, nonce, aad, plaintext, ciphertext, tag)
        }
        BlockingOp::AesCcm8_128Decrypt { key, nonce, aad, ciphertext, plaintext, tag } => {
            aes_ccm8_128_decrypt(key, nonce, aad, ciphertext, plaintext, tag)
        }
        BlockingOp::AesGcm128Encrypt { key, nonce, aad, plaintext, ciphertext, tag } => {
            aes_gcm_128_encrypt(key, nonce, aad, plaintext, ciphertext, tag)
        }
        BlockingOp::AesGcm128Decrypt { key, nonce, aad, ciphertext, plaintext, tag } => {
            aes_gcm_128_decrypt(key, nonce, aad, ciphertext, plaintext, tag)
        }
        BlockingOp::AesGcm256Encrypt { key, nonce, aad, plaintext, ciphertext, tag } => {
            aes_gcm_256_encrypt(key, nonce, aad, plaintext, ciphertext, tag)
        }
        BlockingOp::AesGcm256Decrypt { key, nonce, aad, ciphertext, plaintext, tag } => {
            aes_gcm_256_decrypt(key, nonce, aad, ciphertext, plaintext, tag)
        }
        BlockingOp::RngFill { .. } => Err(CryptoError::Unsupported),
    }
}

// ------------------------------------------------------------------
// AES-128-ECB
// ------------------------------------------------------------------

pub fn aes_128_ecb_encrypt(block: &mut [u8; 16], key: &[u8; 16]) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::Aes128EcbEncrypt { block, key },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    let cipher = Aes128::new(key.into());
    cipher.encrypt_block(block.into());
    Ok(())
}

pub fn aes_128_ecb_decrypt(block: &mut [u8; 16], key: &[u8; 16]) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::Aes128EcbDecrypt { block, key },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    let cipher = Aes128::new(key.into());
    cipher.decrypt_block(block.into());
    Ok(())
}

// ------------------------------------------------------------------
// AES-128-CMAC
// ------------------------------------------------------------------

pub fn aes_128_cmac(key: &[u8; 16], data: &[u8], out: &mut [u8; 16]) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::Aes128Cmac { key, data, out },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    let mut mac = Cmac::<Aes128>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    mac.update(data);
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(())
}

// ------------------------------------------------------------------
// AES-CCM-128 (16-byte tag)
// ------------------------------------------------------------------

pub fn aes_ccm_128_encrypt(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; 16],
) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::AesCcm128Encrypt { key, nonce, aad, plaintext, ciphertext, tag },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    if nonce.len() != 13 {
        return Err(CryptoError::InvalidInput);
    }
    if ciphertext.len() < plaintext.len() {
        return Err(CryptoError::BufferTooSmall);
    }
    let cipher = Ccm128::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = GenericArray::from_slice(nonce);
    ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    let t = cipher
        .encrypt_in_place_detached(nonce, aad, &mut ciphertext[..plaintext.len()])
        .map_err(|_| CryptoError::InvalidInput)?;
    tag.copy_from_slice(&t);
    Ok(())
}

pub fn aes_ccm_128_decrypt(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::AesCcm128Decrypt { key, nonce, aad, ciphertext, plaintext, tag },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    if nonce.len() != 13 {
        return Err(CryptoError::InvalidInput);
    }
    if plaintext.len() < ciphertext.len() {
        return Err(CryptoError::BufferTooSmall);
    }
    let cipher = Ccm128::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = GenericArray::from_slice(nonce);
    plaintext[..ciphertext.len()].copy_from_slice(ciphertext);
    cipher
        .decrypt_in_place_detached(
            nonce,
            aad,
            &mut plaintext[..ciphertext.len()],
            GenericArray::from_slice(tag),
        )
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(())
}

// ------------------------------------------------------------------
// AES-CCM8-128 (8-byte tag)
// ------------------------------------------------------------------

pub fn aes_ccm8_128_encrypt(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; 8],
) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::AesCcm8_128Encrypt { key, nonce, aad, plaintext, ciphertext, tag },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    if nonce.len() != 13 {
        return Err(CryptoError::InvalidInput);
    }
    if ciphertext.len() < plaintext.len() {
        return Err(CryptoError::BufferTooSmall);
    }
    let cipher = Ccm8_128::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = GenericArray::from_slice(nonce);
    ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    let t = cipher
        .encrypt_in_place_detached(nonce, aad, &mut ciphertext[..plaintext.len()])
        .map_err(|_| CryptoError::InvalidInput)?;
    tag.copy_from_slice(&t);
    Ok(())
}

pub fn aes_ccm8_128_decrypt(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
    tag: &[u8; 8],
) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::AesCcm8_128Decrypt { key, nonce, aad, ciphertext, plaintext, tag },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    if nonce.len() != 13 {
        return Err(CryptoError::InvalidInput);
    }
    if plaintext.len() < ciphertext.len() {
        return Err(CryptoError::BufferTooSmall);
    }
    let cipher = Ccm8_128::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = GenericArray::from_slice(nonce);
    plaintext[..ciphertext.len()].copy_from_slice(ciphertext);
    cipher
        .decrypt_in_place_detached(
            nonce,
            aad,
            &mut plaintext[..ciphertext.len()],
            GenericArray::from_slice(tag),
        )
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(())
}

// ------------------------------------------------------------------
// AES-GCM-128
// ------------------------------------------------------------------

pub fn aes_gcm_128_encrypt(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; 16],
) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::AesGcm128Encrypt { key, nonce, aad, plaintext, ciphertext, tag },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidInput);
    }
    if ciphertext.len() < plaintext.len() {
        return Err(CryptoError::BufferTooSmall);
    }
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = GenericArray::from_slice(nonce);
    ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    let t = cipher
        .encrypt_in_place_detached(nonce, aad, &mut ciphertext[..plaintext.len()])
        .map_err(|_| CryptoError::InvalidInput)?;
    tag.copy_from_slice(&t);
    Ok(())
}

pub fn aes_gcm_128_decrypt(
    key: &[u8; 16],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::AesGcm128Decrypt { key, nonce, aad, ciphertext, plaintext, tag },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidInput);
    }
    if plaintext.len() < ciphertext.len() {
        return Err(CryptoError::BufferTooSmall);
    }
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = GenericArray::from_slice(nonce);
    plaintext[..ciphertext.len()].copy_from_slice(ciphertext);
    cipher
        .decrypt_in_place_detached(
            nonce,
            aad,
            &mut plaintext[..ciphertext.len()],
            GenericArray::from_slice(tag),
        )
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(())
}

// ------------------------------------------------------------------
// AES-GCM-256
// ------------------------------------------------------------------

pub fn aes_gcm_256_encrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; 16],
) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::AesGcm256Encrypt { key, nonce, aad, plaintext, ciphertext, tag },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidInput);
    }
    if ciphertext.len() < plaintext.len() {
        return Err(CryptoError::BufferTooSmall);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = GenericArray::from_slice(nonce);
    ciphertext[..plaintext.len()].copy_from_slice(plaintext);
    let t = cipher
        .encrypt_in_place_detached(nonce, aad, &mut ciphertext[..plaintext.len()])
        .map_err(|_| CryptoError::InvalidInput)?;
    tag.copy_from_slice(&t);
    Ok(())
}

pub fn aes_gcm_256_decrypt(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), CryptoError> {
    match embassy_crypto_driver::CryptoDriver::dispatch_blocking(
        BlockingOp::AesGcm256Decrypt { key, nonce, aad, ciphertext, plaintext, tag },
    ) {
        Some(Ok(())) => return Ok(()),
        Some(Err(CryptoError::Unsupported)) | None => {}
        Some(Err(e)) => return Err(e),
    }
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidInput);
    }
    if plaintext.len() < ciphertext.len() {
        return Err(CryptoError::BufferTooSmall);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;
    let nonce = GenericArray::from_slice(nonce);
    plaintext[..ciphertext.len()].copy_from_slice(ciphertext);
    cipher
        .decrypt_in_place_detached(
            nonce,
            aad,
            &mut plaintext[..ciphertext.len()],
            GenericArray::from_slice(tag),
        )
        .map_err(|_| CryptoError::InvalidSignature)?;
    Ok(())
}

// ------------------------------------------------------------------
// Streaming Hash / HMAC contexts with software fallback
// ------------------------------------------------------------------

use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use md5::Md5;
use hmac::{Hmac, Mac as HmacMac};
use digest::Update;
use spin::Mutex;

const MAX_CONTEXTS: usize = 4;
const SOFTWARE_HANDLE_BASE: usize = 0x1000;

#[derive(Clone)]
enum SoftwareContext {
    Sha1(Sha1),
    Md5(Md5),
    Sha224(Sha224),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512_224(Sha512_224),
    Sha512_256(Sha512_256),
    Sha512(Sha512),
    HmacSha256(Hmac<Sha256>),
    HmacSha384(Hmac<Sha384>),
    HmacSha512(Hmac<Sha512>),
    Empty,
}

static CONTEXTS: Mutex<[SoftwareContext; MAX_CONTEXTS]> = Mutex::new([
    SoftwareContext::Empty,
    SoftwareContext::Empty,
    SoftwareContext::Empty,
    SoftwareContext::Empty,
]);

fn alloc_context(ctx: SoftwareContext) -> Result<ContextHandle, CryptoError> {
    let mut slots = CONTEXTS.lock();
    for (i, slot) in slots.iter_mut().enumerate() {
        if matches!(slot, SoftwareContext::Empty) {
            *slot = ctx;
            return Ok(ContextHandle(SOFTWARE_HANDLE_BASE + i));
        }
    }
    Err(CryptoError::HardwareError)
}

fn with_context<F, R>(handle: ContextHandle, f: F) -> Result<R, CryptoError>
where
    F: FnOnce(&mut SoftwareContext) -> Result<R, CryptoError>,
{
    let idx = handle.0.wrapping_sub(SOFTWARE_HANDLE_BASE);
    if idx >= MAX_CONTEXTS {
        return Err(CryptoError::InvalidInput);
    }
    let mut slots = CONTEXTS.lock();
    f(&mut slots[idx])
}

fn context_update(ctx: &mut SoftwareContext, data: &[u8]) -> Result<(), CryptoError> {
    match ctx {
        SoftwareContext::Sha1(c) => c.update(data),
        SoftwareContext::Md5(c) => c.update(data),
        SoftwareContext::Sha224(c) => c.update(data),
        SoftwareContext::Sha256(c) => c.update(data),
        SoftwareContext::Sha384(c) => c.update(data),
        SoftwareContext::Sha512_224(c) => c.update(data),
        SoftwareContext::Sha512_256(c) => c.update(data),
        SoftwareContext::Sha512(c) => c.update(data),
        SoftwareContext::HmacSha256(c) => c.update(data),
        SoftwareContext::HmacSha384(c) => c.update(data),
        SoftwareContext::HmacSha512(c) => c.update(data),
        SoftwareContext::Empty => return Err(CryptoError::InvalidInput),
    }
    Ok(())
}

fn context_finalize(ctx: &mut SoftwareContext, out: &mut [u8]) -> Result<(), CryptoError> {
    let mut taken = SoftwareContext::Empty;
    core::mem::swap(ctx, &mut taken);

    let expected_len = match &taken {
        SoftwareContext::Sha1(_) => 20,
        SoftwareContext::Md5(_) => 16,
        SoftwareContext::Sha224(_) => 28,
        SoftwareContext::Sha256(_) => 32,
        SoftwareContext::Sha384(_) => 48,
        SoftwareContext::Sha512_224(_) => 28,
        SoftwareContext::Sha512_256(_) => 32,
        SoftwareContext::Sha512(_) => 64,
        SoftwareContext::HmacSha256(_) => 32,
        SoftwareContext::HmacSha384(_) => 48,
        SoftwareContext::HmacSha512(_) => 64,
        SoftwareContext::Empty => return Err(CryptoError::InvalidInput),
    };

    if out.len() < expected_len {
        return Err(CryptoError::BufferTooSmall);
    }

    match taken {
        SoftwareContext::Sha1(c) => out[..20].copy_from_slice(&c.finalize_fixed()),
        SoftwareContext::Md5(c) => out[..16].copy_from_slice(&c.finalize_fixed()),
        SoftwareContext::Sha224(c) => out[..28].copy_from_slice(&c.finalize_fixed()),
        SoftwareContext::Sha256(c) => out[..32].copy_from_slice(&c.finalize_fixed()),
        SoftwareContext::Sha384(c) => out[..48].copy_from_slice(&c.finalize_fixed()),
        SoftwareContext::Sha512_224(c) => out[..28].copy_from_slice(&c.finalize_fixed()),
        SoftwareContext::Sha512_256(c) => out[..32].copy_from_slice(&c.finalize_fixed()),
        SoftwareContext::Sha512(c) => out[..64].copy_from_slice(&c.finalize_fixed()),
        SoftwareContext::HmacSha256(c) => {
            let result = c.finalize();
            out[..32].copy_from_slice(&result.into_bytes());
        }
        SoftwareContext::HmacSha384(c) => {
            let result = c.finalize();
            out[..48].copy_from_slice(&result.into_bytes());
        }
        SoftwareContext::HmacSha512(c) => {
            let result = c.finalize();
            out[..64].copy_from_slice(&result.into_bytes());
        }
        SoftwareContext::Empty => unreachable!(),
    }
    Ok(())
}

/// Initialize a streaming hash or HMAC context.
///
/// Tries the linked driver first; falls back to a software implementation
/// if the driver reports `Unsupported`.
pub fn try_context_init(alg: Algorithm<'_>) -> Result<ContextHandle, CryptoError> {
    match embassy_crypto_driver::CryptoDriver::try_context_init(alg) {
        Ok(handle) => return Ok(handle),
        Err(CryptoError::Unsupported) => {}
        Err(e) => return Err(e),
    }

    let ctx = match alg {
        Algorithm::SHA1 => SoftwareContext::Sha1(Sha1::default()),
        Algorithm::MD5 => SoftwareContext::Md5(Md5::default()),
        Algorithm::SHA224 => SoftwareContext::Sha224(Sha224::default()),
        Algorithm::SHA256 => SoftwareContext::Sha256(Sha256::default()),
        Algorithm::SHA384 => SoftwareContext::Sha384(Sha384::default()),
        Algorithm::SHA512_224 => SoftwareContext::Sha512_224(Sha512_224::default()),
        Algorithm::SHA512_256 => SoftwareContext::Sha512_256(Sha512_256::default()),
        Algorithm::SHA512 => SoftwareContext::Sha512(Sha512::default()),
        Algorithm::HmacSha256 { key } => SoftwareContext::HmacSha256(
            Hmac::<Sha256>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?,
        ),
        Algorithm::HmacSha384 { key } => SoftwareContext::HmacSha384(
            Hmac::<Sha384>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?,
        ),
        Algorithm::HmacSha512 { key } => SoftwareContext::HmacSha512(
            Hmac::<Sha512>::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?,
        ),
    };

    alloc_context(ctx)
}

/// Update a streaming hash or HMAC context with more data.
///
/// Routes to the linked driver for driver-managed handles and to the
/// software fallback for handles allocated by `try_context_init`.
pub fn try_context_update(handle: ContextHandle, data: &[u8]) -> Result<(), CryptoError> {
    if handle.0 >= SOFTWARE_HANDLE_BASE {
        with_context(handle, |ctx| context_update(ctx, data))
    } else {
        embassy_crypto_driver::CryptoDriver::try_context_update(handle, data)
    }
}

/// Clone an existing streaming hash or HMAC context.
///
/// Tries the linked driver first; falls back to cloning the software
/// context if the driver reports `Unsupported`.
pub fn try_context_clone(handle: ContextHandle) -> Result<ContextHandle, CryptoError> {
    match embassy_crypto_driver::CryptoDriver::try_context_clone(handle) {
        Ok(new_handle) => return Ok(new_handle),
        Err(CryptoError::Unsupported) => {}
        Err(e) => return Err(e),
    }

    if handle.0 >= SOFTWARE_HANDLE_BASE {
        let mut src: Option<SoftwareContext> = None;
        with_context(handle, |ctx| {
            src = Some(ctx.clone());
            Ok(())
        })?;
        alloc_context(src.unwrap())
    } else {
        Err(CryptoError::Unsupported)
    }
}

/// Finalize a streaming hash or HMAC context and write the digest.
///
/// Routes to the linked driver for driver-managed handles and to the
/// software fallback for handles allocated by `try_context_init`.
pub fn try_context_finalize(handle: ContextHandle, out: &mut [u8]) -> Result<(), CryptoError> {
    if handle.0 >= SOFTWARE_HANDLE_BASE {
        with_context(handle, |ctx| context_finalize(ctx, out))
    } else {
        embassy_crypto_driver::CryptoDriver::try_context_finalize(handle, out)
    }
}
