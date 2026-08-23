#![cfg_attr(not(test), no_std)]

//! `BlockingCryptoDriver` wrapper around any [`embedded-cal::Cal`] implementation.
//!
//! This crate bridges the [`embassy_crypto_driver::BlockingCryptoDriver`] trait
//! to the [`embedded-cal`] abstraction layer. It is intended to wrap hardware
//! accelerator backends (e.g. `embedded-cal-nrf54l15`, `embedded-cal-stm32wba55`)
//! so that `embassy_crypto` consumers can use them.
//!
//! **Supported:**
//! - SHA-256 (streaming via `HashContext`)
//! - AES-CCM-128/8 (encrypt/decrypt)
//!
//! **Not supported** (returns `CryptoError::Unsupported`):
//! - AES-ECB, AES-CMAC, AES-GCM, AES-CCM-16
//! - HMAC (not exposed by this wrapper)
//! - P-256 / P-384 DH — see below
//! - RSA
//!
//! ## Why P-256 DH does not bridge
//!
//! `embedded-cal` uses **COSE compact representation** for P-256 public keys:
//! 32-byte x-coordinate only. `embassy_crypto_driver` expects **64-byte
//! uncompressed SEC1** points (`x || y`). These are fundamentally different
//! wire formats. Decompressing a compact key to recover `y` requires curve
//! arithmetic that `embedded-cal` does not expose through its trait surface,
//! and the wrapper is generic over `Cal` so it cannot pull in `p256` directly.
//!
//! Additionally, `embedded-cal`'s `DhProvider` only covers key agreement
//! (ECDH). It provides **no ECDSA sign/verify** interface, so
//! `blocking_p256_ecdsa_sign` / `blocking_p256_ecdsa_verify` have no
//! `embedded-cal` equivalent to delegate to.
//!
//! To use hardware-accelerated P-256 with `embassy_crypto`, the driver trait
//! would need to accept compact public keys, or `embedded-cal` would need to
//! expose uncompressed import/export.

use embassy_crypto_driver::{
    Algorithm, BlockingCryptoDriver, Capabilities, CryptoError, HashContext,
};

use embedded_cal::AeadAlgorithm;
use embedded_cal::AeadProvider;
use embedded_cal::Cal;
use embedded_cal::HashAlgorithm;
use embedded_cal::HashProvider;
use embedded_cal::accessor::HashStateOf;

/// Concrete AEAD algorithm type for a given `Cal`.
type CalAeadAlg<C> = <<C as Cal>::AeadProvider as embedded_cal::AeadProvider>::Algorithm;

/// Concrete hash algorithm type for a given `Cal`.
type CalHashAlg<C> = <<C as Cal>::HashProvider as embedded_cal::HashProvider>::Algorithm;

/// Concrete hash state type for a given `Cal`.
type CalHashState<C> = HashStateOf<C>;

/// Crypto driver backed by any `embedded-cal` implementation.
pub struct CalDriver<C: Cal> {
    cal: C,
}

impl<C: Cal> CalDriver<C> {
    /// Wrap an existing `Cal` implementation.
    pub const fn new(cal: C) -> Self {
        Self { cal }
    }

    /// Consume the wrapper and return the inner `Cal`.
    pub fn into_inner(self) -> C {
        self.cal
    }
}

impl<C: Cal> BlockingCryptoDriver for CalDriver<C>
where
    CalHashState<C>: Clone,
{
    fn capabilities(&self) -> Capabilities {
        Capabilities::SHA_256 | Capabilities::AES_128_CCM8
    }

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
        let alg = CalAeadAlg::<C>::from_cose_number(10i8).ok_or(CryptoError::Unsupported)?;
        let aead_key = self.cal.aead().load_from_keydata(alg, key.as_slice());
        ciphertext.copy_from_slice(plaintext);
        let computed_tag = self
            .cal
            .aead()
            .encrypt_in_place(&aead_key, nonce, ciphertext, aad);
        tag.copy_from_slice(computed_tag.as_ref());
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
        let alg = CalAeadAlg::<C>::from_cose_number(10i8).ok_or(CryptoError::Unsupported)?;
        let aead_key = self.cal.aead().load_from_keydata(alg, key.as_slice());
        plaintext.copy_from_slice(ciphertext);
        self.cal
            .aead()
            .decrypt_in_place(&aead_key, nonce, plaintext, tag, aad)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    fn blocking_hash_init(
        &mut self,
        op: Algorithm,
        ctx: &mut HashContext,
    ) -> Result<(), CryptoError> {
        match op {
            Algorithm::SHA256 => {
                let alg =
                    CalHashAlg::<C>::from_cose_number(-16i8).ok_or(CryptoError::Unsupported)?;
                let state = self.cal.hash().init(alg);
                unsafe {
                    core::ptr::write(ctx.0.as_mut_ptr() as *mut CalHashState<C>, state);
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
                let state = unsafe { &mut *(ctx.0.as_mut_ptr() as *mut CalHashState<C>) };
                self.cal.hash().update(state, data);
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
                let state = unsafe { &*(ctx.0.as_ptr() as *const CalHashState<C>) };
                let cloned = state.clone();
                let output = self.cal.hash().finalize(cloned);
                out.copy_from_slice(output.as_ref());
                Ok(())
            }
            _ => Err(CryptoError::Unsupported),
        }
    }
}
