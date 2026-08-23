#![cfg_attr(not(test), no_std)]

//! Software fallback crypto driver using RustCrypto crates.
//!
//! **Implemented:**
//! - AES-128-ECB encrypt/decrypt
//! - AES-128-CMAC
//! - AES-GCM-128/256 encrypt/decrypt
//! - AES-CCM-128/8 encrypt/decrypt
//! - P-256 ECDH, ECDSA sign/verify
//! - P-384 ECDH, ECDSA sign/verify
//!
//! **Skipped (first pass):**
//! - RSA (complex, needs alloc or large stack)
//! - P-256/P-384 keygen (needs RNG — caller should supply entropy)
//! - Hash/HMAC streaming (HashContext 128 bytes too small for RustCrypto state)
//! - RNG fill (security: never silently substitute software RNG for hardware)

use embassy_crypto_driver::{
    Algorithm, BlockingCryptoDriver, Capabilities, CryptoError, HashContext,
};

// AES block cipher
use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as _, generic_array::GenericArray};

// AES-GCM
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm};

// AES-CCM
use aes::cipher::typenum::{U8, U13, U16};
use ccm::Ccm;

// CMAC
use cmac::Cmac;
use digest::{Digest, Mac};
use hmac::Hmac;

// P-256 / P-384
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use signature::hazmat::{PrehashSigner, PrehashVerifier};

// Compile-time assert that RustCrypto Sha256 fits in HashContext.
const _: () = assert!(core::mem::size_of::<sha2::Sha256>() <= 256);
const _: () = assert!(core::mem::size_of::<Hmac<sha2::Sha256>>() <= 256);

/// Zero-sized software crypto driver.
///
/// `Copy` so the runner can use it without a `Mutex`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SwDriver;

impl BlockingCryptoDriver for SwDriver {
    fn capabilities(&self) -> Capabilities {
        Capabilities::SHA_256
            | Capabilities::HMAC_SHA256
            | Capabilities::P256_KEYGEN
            | Capabilities::P384_KEYGEN
            | Capabilities::AES_128_ECB
            | Capabilities::AES_128_CMAC
            | Capabilities::AES_128_GCM
            | Capabilities::AES_256_GCM
            | Capabilities::AES_128_CCM
            | Capabilities::AES_128_CCM8
            | Capabilities::P256_ECDH
            | Capabilities::P256_ECDSA_SIGN
            | Capabilities::P256_ECDSA_VERIFY
            | Capabilities::P384_ECDH
            | Capabilities::P384_ECDSA_SIGN
            | Capabilities::P384_ECDSA_VERIFY
    }

    // ------------------------------------------------------------------
    // AES-128-ECB
    // ------------------------------------------------------------------
    fn blocking_aes_128_ecb_encrypt(
        &mut self,
        block: &mut [u8; 16],
        key: &[u8; 16],
    ) -> Result<(), CryptoError> {
        let cipher = Aes128::new_from_slice(key.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
        Ok(())
    }

    fn blocking_aes_128_ecb_decrypt(
        &mut self,
        block: &mut [u8; 16],
        key: &[u8; 16],
    ) -> Result<(), CryptoError> {
        let cipher = Aes128::new_from_slice(key.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        Ok(())
    }

    // ------------------------------------------------------------------
    // AES-128-CMAC
    // ------------------------------------------------------------------
    fn blocking_aes_128_cmac(
        &mut self,
        key: &[u8; 16],
        data: &[u8],
        out: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key.as_slice())
            .map_err(|_| CryptoError::InvalidKey)?;
        Mac::update(&mut mac, data);
        let result = mac.finalize();
        out.copy_from_slice(result.into_bytes().as_slice());
        Ok(())
    }

    // ------------------------------------------------------------------
    // AES-GCM-128
    // ------------------------------------------------------------------
    fn blocking_aes_gcm_128_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput);
        }
        if ciphertext.len() != plaintext.len() {
            return Err(CryptoError::InvalidInput);
        }
        let cipher =
            Aes128Gcm::new_from_slice(key.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_ga = GenericArray::from_slice(nonce);
        ciphertext.copy_from_slice(plaintext);
        let computed_tag = cipher
            .encrypt_in_place_detached(nonce_ga, aad, ciphertext)
            .map_err(|_| CryptoError::InvalidInput)?;
        tag.copy_from_slice(computed_tag.as_slice());
        Ok(())
    }

    fn blocking_aes_gcm_128_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput);
        }
        if plaintext.len() != ciphertext.len() {
            return Err(CryptoError::InvalidInput);
        }
        let cipher =
            Aes128Gcm::new_from_slice(key.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_ga = GenericArray::from_slice(nonce);
        plaintext.copy_from_slice(ciphertext);
        cipher
            .decrypt_in_place_detached(nonce_ga, aad, plaintext, GenericArray::from_slice(tag))
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // AES-GCM-256
    // ------------------------------------------------------------------
    fn blocking_aes_gcm_256_encrypt(
        &mut self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput);
        }
        if ciphertext.len() != plaintext.len() {
            return Err(CryptoError::InvalidInput);
        }
        let cipher =
            Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_ga = GenericArray::from_slice(nonce);
        ciphertext.copy_from_slice(plaintext);
        let computed_tag = cipher
            .encrypt_in_place_detached(nonce_ga, aad, ciphertext)
            .map_err(|_| CryptoError::InvalidInput)?;
        tag.copy_from_slice(computed_tag.as_slice());
        Ok(())
    }

    fn blocking_aes_gcm_256_decrypt(
        &mut self,
        key: &[u8; 32],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        if nonce.len() != 12 {
            return Err(CryptoError::InvalidInput);
        }
        if plaintext.len() != ciphertext.len() {
            return Err(CryptoError::InvalidInput);
        }
        let cipher =
            Aes256Gcm::new_from_slice(key.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_ga = GenericArray::from_slice(nonce);
        plaintext.copy_from_slice(ciphertext);
        cipher
            .decrypt_in_place_detached(nonce_ga, aad, plaintext, GenericArray::from_slice(tag))
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // AES-CCM-128 (16-byte tag)
    // ------------------------------------------------------------------
    fn blocking_aes_ccm_128_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        if nonce.len() != 13 {
            return Err(CryptoError::InvalidInput);
        }
        if ciphertext.len() != plaintext.len() {
            return Err(CryptoError::InvalidInput);
        }
        type Ccm128 = Ccm<Aes128, U16, U13>;
        let cipher = Ccm128::new_from_slice(key.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_ga = GenericArray::from_slice(nonce);
        ciphertext.copy_from_slice(plaintext);
        let computed_tag = cipher
            .encrypt_in_place_detached(nonce_ga, aad, ciphertext)
            .map_err(|_| CryptoError::InvalidInput)?;
        tag.copy_from_slice(computed_tag.as_slice());
        Ok(())
    }

    fn blocking_aes_ccm_128_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        if nonce.len() != 13 {
            return Err(CryptoError::InvalidInput);
        }
        if plaintext.len() != ciphertext.len() {
            return Err(CryptoError::InvalidInput);
        }
        type Ccm128 = Ccm<Aes128, U16, U13>;
        let cipher = Ccm128::new_from_slice(key.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_ga = GenericArray::from_slice(nonce);
        plaintext.copy_from_slice(ciphertext);
        cipher
            .decrypt_in_place_detached(nonce_ga, aad, plaintext, GenericArray::from_slice(tag))
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // AES-CCM8-128 (8-byte tag)
    // ------------------------------------------------------------------
    fn blocking_aes_ccm8_128_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; 8],
    ) -> Result<(), CryptoError> {
        if nonce.len() != 13 {
            return Err(CryptoError::InvalidInput);
        }
        if ciphertext.len() != plaintext.len() {
            return Err(CryptoError::InvalidInput);
        }
        type Ccm8_128 = Ccm<Aes128, U8, U13>;
        let cipher =
            Ccm8_128::new_from_slice(key.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_ga = GenericArray::from_slice(nonce);
        ciphertext.copy_from_slice(plaintext);
        let computed_tag = cipher
            .encrypt_in_place_detached(nonce_ga, aad, ciphertext)
            .map_err(|_| CryptoError::InvalidInput)?;
        tag.copy_from_slice(computed_tag.as_slice());
        Ok(())
    }

    fn blocking_aes_ccm8_128_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), CryptoError> {
        if nonce.len() != 13 {
            return Err(CryptoError::InvalidInput);
        }
        if plaintext.len() != ciphertext.len() {
            return Err(CryptoError::InvalidInput);
        }
        type Ccm8_128 = Ccm<Aes128, U8, U13>;
        let cipher =
            Ccm8_128::new_from_slice(key.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        let nonce_ga = GenericArray::from_slice(nonce);
        plaintext.copy_from_slice(ciphertext);
        cipher
            .decrypt_in_place_detached(nonce_ga, aad, plaintext, GenericArray::from_slice(tag))
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // P-256
    // ------------------------------------------------------------------
    fn blocking_p256_ecdh(
        &mut self,
        secret_key: &[u8; 32],
        public_key: &[u8; 64],
        shared_secret: &mut [u8; 32],
    ) -> Result<(), CryptoError> {
        let secret = p256::SecretKey::from_slice(secret_key.as_slice())
            .map_err(|_| CryptoError::InvalidKey)?;
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(public_key.as_slice());
        let public =
            p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidKey)?;
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
        shared_secret.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Ok(())
    }

    fn blocking_p256_ecdsa_sign(
        &mut self,
        secret_key: &[u8; 32],
        digest: &[u8; 32],
        signature: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        let signing_key =
            P256SigningKey::from_bytes(GenericArray::from_slice(secret_key.as_slice()))
                .map_err(|_| CryptoError::InvalidKey)?;
        let sig: P256Signature = signing_key
            .sign_prehash(digest.as_slice())
            .map_err(|_| CryptoError::HardwareError)?;
        signature.copy_from_slice(sig.to_bytes().as_slice());
        Ok(())
    }

    fn blocking_p256_ecdsa_verify(
        &mut self,
        public_key: &[u8; 64],
        digest: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), CryptoError> {
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(public_key.as_slice());
        let verifying_key =
            P256VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidKey)?;
        let sig = P256Signature::from_bytes(GenericArray::from_slice(signature.as_slice()))
            .map_err(|_| CryptoError::InvalidSignature)?;
        verifying_key
            .verify_prehash(digest.as_slice(), &sig)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // P-384
    // ------------------------------------------------------------------
    fn blocking_p384_ecdh(
        &mut self,
        secret_key: &[u8; 48],
        public_key: &[u8; 96],
        shared_secret: &mut [u8; 48],
    ) -> Result<(), CryptoError> {
        let secret = p384::SecretKey::from_slice(secret_key.as_slice())
            .map_err(|_| CryptoError::InvalidKey)?;
        let mut sec1 = [0u8; 97];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(public_key.as_slice());
        let public =
            p384::PublicKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidKey)?;
        let shared = p384::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
        shared_secret.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Ok(())
    }

    fn blocking_p384_ecdsa_sign(
        &mut self,
        secret_key: &[u8; 48],
        digest: &[u8; 48],
        signature: &mut [u8; 96],
    ) -> Result<(), CryptoError> {
        let signing_key =
            P384SigningKey::from_bytes(GenericArray::from_slice(secret_key.as_slice()))
                .map_err(|_| CryptoError::InvalidKey)?;
        let sig: P384Signature = signing_key
            .sign_prehash(digest.as_slice())
            .map_err(|_| CryptoError::HardwareError)?;
        signature.copy_from_slice(sig.to_bytes().as_slice());
        Ok(())
    }

    fn blocking_p384_ecdsa_verify(
        &mut self,
        public_key: &[u8; 96],
        digest: &[u8; 48],
        signature: &[u8; 96],
    ) -> Result<(), CryptoError> {
        let mut sec1 = [0u8; 97];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(public_key.as_slice());
        let verifying_key =
            P384VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| CryptoError::InvalidKey)?;
        let sig = P384Signature::from_bytes(GenericArray::from_slice(signature.as_slice()))
            .map_err(|_| CryptoError::InvalidSignature)?;
        verifying_key
            .verify_prehash(digest.as_slice(), &sig)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Hash streaming (SHA-256 only — fits in 128-byte HashContext)
    // ------------------------------------------------------------------
    fn blocking_hash_init(
        &mut self,
        op: Algorithm,
        ctx: &mut HashContext,
    ) -> Result<(), CryptoError> {
        match op {
            Algorithm::SHA256 => {
                let hasher = sha2::Sha256::new();
                unsafe {
                    core::ptr::write(ctx.0.as_mut_ptr() as *mut sha2::Sha256, hasher);
                }
                Ok(())
            }
            _ => Err(CryptoError::Unsupported),
        }
    }

    fn blocking_hash_update(
        &mut self,
        op: Algorithm,
        ctx: &mut HashContext,
        data: &[u8],
    ) -> Result<(), CryptoError> {
        match op {
            Algorithm::SHA256 => {
                let hasher = unsafe { &mut *(ctx.0.as_mut_ptr() as *mut sha2::Sha256) };
                digest::Update::update(hasher, data);
                Ok(())
            }
            Algorithm::HmacSha256 => {
                let mac = unsafe { &mut *(ctx.0.as_mut_ptr() as *mut Hmac<sha2::Sha256>) };
                digest::Mac::update(mac, data);
                Ok(())
            }
            _ => Err(CryptoError::Unsupported),
        }
    }

    fn blocking_hash_finalize(
        &mut self,
        op: Algorithm,
        ctx: &mut HashContext,
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        match op {
            Algorithm::SHA256 => {
                let hasher = unsafe { &*(ctx.0.as_ptr() as *const sha2::Sha256) };
                let cloned = hasher.clone();
                let mut ga = digest::Output::<sha2::Sha256>::default();
                digest::FixedOutput::finalize_into(cloned, &mut ga);
                out.copy_from_slice(ga.as_slice());
                Ok(())
            }
            Algorithm::HmacSha256 => {
                let mac = unsafe { &*(ctx.0.as_ptr() as *const Hmac<sha2::Sha256>) };
                let cloned = mac.clone();
                let result = digest::Mac::finalize(cloned);
                out.copy_from_slice(result.into_bytes().as_slice());
                Ok(())
            }
            _ => Err(CryptoError::Unsupported),
        }
    }

    fn blocking_hmac_init(
        &mut self,
        op: Algorithm,
        key: &[u8],
        ctx: &mut HashContext,
    ) -> Result<(), CryptoError> {
        match op {
            Algorithm::HmacSha256 => {
                let mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(key)
                    .map_err(|_| CryptoError::InvalidKey)?;
                unsafe {
                    core::ptr::write(ctx.0.as_mut_ptr() as *mut Hmac<sha2::Sha256>, mac);
                }
                Ok(())
            }
            _ => Err(CryptoError::Unsupported),
        }
    }

    fn blocking_p256_keygen(
        &mut self,
        secret_key: &[u8; 32],
        public_key: &mut [u8; 64],
    ) -> Result<(), CryptoError> {
        let secret = p256::SecretKey::from_slice(secret_key.as_slice())
            .map_err(|_| CryptoError::InvalidKey)?;
        let pk = p256::PublicKey::from_secret_scalar(&secret.to_nonzero_scalar());
        let point = pk.to_encoded_point(false);
        public_key[..32].copy_from_slice(point.x().ok_or(CryptoError::InvalidKey)?.as_slice());
        public_key[32..].copy_from_slice(point.y().ok_or(CryptoError::InvalidKey)?.as_slice());
        Ok(())
    }

    fn blocking_p384_keygen(
        &mut self,
        secret_key: &[u8; 48],
        public_key: &mut [u8; 96],
    ) -> Result<(), CryptoError> {
        let secret = p384::SecretKey::from_slice(secret_key.as_slice())
            .map_err(|_| CryptoError::InvalidKey)?;
        let pk = p384::PublicKey::from_secret_scalar(&secret.to_nonzero_scalar());
        let point = pk.to_encoded_point(false);
        public_key[..48].copy_from_slice(point.x().ok_or(CryptoError::InvalidKey)?.as_slice());
        public_key[48..].copy_from_slice(point.y().ok_or(CryptoError::InvalidKey)?.as_slice());
        Ok(())
    }
}
