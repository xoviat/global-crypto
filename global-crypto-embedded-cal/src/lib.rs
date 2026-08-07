#![no_std]

//! Bridge crate: adapts any `embedded-cal::Cal` implementation to the
//! `global_crypto::CryptoDriver` dyn-safe trait.

use core::cell::RefCell;
use critical_section::Mutex;
use embedded_cal::{
    AadGenerator, AeadAlgorithm, AeadProvider as _, Cal, DhAlgorithm, DhProvider as _,
    HashAlgorithm, HashProvider as _, HkdfProvider as _, HmacAlgorithm, HmacProvider as _,
};
use global_crypto::{
    AeadAlgorithmId, CryptoDriver, CryptoError, DhAlgorithmId, HashAlgorithmId, HmacAlgorithmId,
};

// ============================================================================
// Bridge struct
// ============================================================================

pub struct EmbeddedCalBridge<C: Cal + Send> {
    cal: Mutex<RefCell<C>>,
}

impl<C: Cal + Send> EmbeddedCalBridge<C> {
    pub const fn new(cal: C) -> Self {
        Self {
            cal: Mutex::new(RefCell::new(cal)),
        }
    }
}

// ============================================================================
// AadGenerator adapter
// ============================================================================

struct SingleAad<'a>(&'a [u8]);

impl<'a> AadGenerator for SingleAad<'a> {
    fn items(&self) -> impl Iterator<Item = &[u8]> {
        core::iter::once(self.0)
    }
}

// ============================================================================
// CryptoDriver implementation
// ============================================================================

impl<C: Cal + Send> CryptoDriver for EmbeddedCalBridge<C> {
    fn supports_aead(&self, alg: AeadAlgorithmId) -> bool {
        map_aead_alg::<C>(alg).is_ok()
    }

    fn supports_hash(&self, alg: HashAlgorithmId) -> bool {
        map_hash_alg::<C>(alg).is_ok()
    }

    fn supports_hmac(&self, alg: HmacAlgorithmId) -> bool {
        map_hmac_alg::<C>(alg).is_ok()
    }

    fn supports_dh(&self, alg: DhAlgorithmId) -> bool {
        map_dh_alg::<C>(alg).is_ok()
    }

    fn supports_hkdf(&self, alg: HmacAlgorithmId) -> bool {
        map_hmac_alg::<C>(alg).is_ok()
    }

    fn aead_encrypt(
        &self,
        alg: AeadAlgorithmId,
        key: &[u8],
        nonce: &[u8],
        message: &mut [u8],
        aad: &[u8],
        tag_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        critical_section::with(|cs| {
            let mut cal = self.cal.borrow(cs).borrow_mut();
            let aead = cal.aead();

            let alg = map_aead_alg::<C>(alg)?;
            let rich_key = aead.load_from_keydata(alg, key);
            let rich_tag = aead.encrypt_in_place(&rich_key, nonce, message, SingleAad(aad));

            let tag_bytes = rich_tag.as_ref();
            if tag_out.len() != tag_bytes.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            tag_out.copy_from_slice(tag_bytes);
            Ok(())
        })
    }

    fn aead_decrypt(
        &self,
        alg: AeadAlgorithmId,
        key: &[u8],
        nonce: &[u8],
        message: &mut [u8],
        tag: &[u8],
        aad: &[u8],
    ) -> Result<(), CryptoError> {
        critical_section::with(|cs| {
            let mut cal = self.cal.borrow(cs).borrow_mut();
            let aead = cal.aead();

            let alg = map_aead_alg::<C>(alg)?;
            let rich_key = aead.load_from_keydata(alg, key);
            aead.decrypt_in_place(&rich_key, nonce, message, tag, SingleAad(aad))
                .map_err(|_| CryptoError::DecryptionFailed)
        })
    }

    fn hash(&self, alg: HashAlgorithmId, data: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        critical_section::with(|cs| {
            let mut cal = self.cal.borrow(cs).borrow_mut();
            let hash = cal.hash();

            let alg = map_hash_alg::<C>(alg)?;
            let result = hash.hash(alg, data);
            let bytes = result.as_ref();

            if out.len() != bytes.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            out.copy_from_slice(bytes);
            Ok(())
        })
    }

    fn hmac(
        &self,
        alg: HmacAlgorithmId,
        key: &[u8],
        data: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        critical_section::with(|cs| {
            let mut cal = self.cal.borrow(cs).borrow_mut();
            let hmac = cal.hmac();

            let alg = map_hmac_alg::<C>(alg)?;
            let result = hmac.hmac_with_keydata(alg, key, data);
            let bytes = result.as_ref();

            if out.len() != bytes.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            out.copy_from_slice(bytes);
            Ok(())
        })
    }

    fn dh_generate_keypair(
        &self,
        alg: DhAlgorithmId,
        pubkey_out: &mut [u8],
        seckey_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        critical_section::with(|cs| {
            let mut cal = self.cal.borrow(cs).borrow_mut();
            let dh = cal.dh();

            let alg = map_dh_alg::<C>(alg)?;
            let visible_seckey = dh.generate_visible(alg.clone());

            // Export secret key bytes before consuming visible_seckey via .into()
            {
                let exported = dh.export_secretkey_bytes(&visible_seckey);
                let seckey_ref = exported.as_ref();
                if seckey_out.len() != seckey_ref.len() {
                    return Err(CryptoError::BufferTooSmall);
                }
                seckey_out.copy_from_slice(seckey_ref);
            }

            let seckey: <C::DhProvider as embedded_cal::DhProvider>::SecretKey =
                visible_seckey.into();
            let pubkey = dh.public_key(&seckey);

            let exported = dh.export_publickey_bytes(&pubkey);
            let pubkey_ref = exported.as_ref();
            if pubkey_out.len() != pubkey_ref.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            pubkey_out.copy_from_slice(pubkey_ref);
            Ok(())
        })
    }

    fn dh_shared_secret(
        &self,
        alg: DhAlgorithmId,
        seckey: &[u8],
        pubkey: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        critical_section::with(|cs| {
            let mut cal = self.cal.borrow(cs).borrow_mut();
            let dh = cal.dh();

            let alg = map_dh_alg::<C>(alg)?;
            let visible_seckey = dh
                .import_secretkey_bytes(alg.clone(), seckey)
                .map_err(|_| CryptoError::ImportError)?;
            let seckey: <C::DhProvider as embedded_cal::DhProvider>::SecretKey =
                visible_seckey.into();
            let pubkey = dh
                .import_publickey_bytes(alg, pubkey)
                .map_err(|_| CryptoError::ImportError)?;

            let shared = dh
                .shared_secret(&seckey, &pubkey)
                .map_err(|_| CryptoError::IncompatibleKeys)?;
            let bytes = dh.raw_secret_bytes(&shared);

            let bytes_ref = bytes.as_ref();
            if out.len() != bytes_ref.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            out.copy_from_slice(bytes_ref);
            Ok(())
        })
    }

    fn hkdf_extract(
        &self,
        alg: HmacAlgorithmId,
        salt: Option<&[u8]>,
        ikm: &[u8],
        out: &mut [u8],
    ) -> Result<(), CryptoError> {
        critical_section::with(|cs| {
            let mut cal = self.cal.borrow(cs).borrow_mut();
            let alg = map_hmac_alg::<C>(alg)?;

            let prk = cal
                .hmac()
                .hkdf_extract(alg, salt, ikm)
                .map_err(|_| CryptoError::BufferTooSmall)?;

            let bytes = prk.as_ref();
            if out.len() != bytes.len() {
                return Err(CryptoError::BufferTooSmall);
            }
            out.copy_from_slice(bytes);
            Ok(())
        })
    }

    fn hkdf_expand(
        &self,
        alg: HmacAlgorithmId,
        prk: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), CryptoError> {
        critical_section::with(|cs| {
            let mut cal = self.cal.borrow(cs).borrow_mut();
            let alg = map_hmac_alg::<C>(alg)?;

            cal.hmac()
                .hkdf_expand(alg, prk, info, okm)
                .map_err(|_| CryptoError::BufferTooSmall)
        })
    }
}

// ============================================================================
// Algorithm mapping
// ============================================================================

fn map_aead_alg<C: Cal>(
    alg: AeadAlgorithmId,
) -> Result<<C::AeadProvider as embedded_cal::AeadProvider>::Algorithm, CryptoError> {
    match alg {
        AeadAlgorithmId::AesCcm16_64_128 => {
            <C::AeadProvider as embedded_cal::AeadProvider>::Algorithm::from_cose_number(10i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        AeadAlgorithmId::AesCcm16_128_128 => {
            <C::AeadProvider as embedded_cal::AeadProvider>::Algorithm::from_cose_number(30i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        AeadAlgorithmId::Aes128Gcm => {
            <C::AeadProvider as embedded_cal::AeadProvider>::Algorithm::from_cose_number(1i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        AeadAlgorithmId::Aes256Gcm => {
            <C::AeadProvider as embedded_cal::AeadProvider>::Algorithm::from_cose_number(3i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn map_hash_alg<C: Cal>(
    alg: HashAlgorithmId,
) -> Result<<C::HashProvider as embedded_cal::HashProvider>::Algorithm, CryptoError> {
    match alg {
        HashAlgorithmId::Sha256 => {
            <C::HashProvider as embedded_cal::HashProvider>::Algorithm::from_cose_number(-16i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        HashAlgorithmId::Sha384 => {
            <C::HashProvider as embedded_cal::HashProvider>::Algorithm::from_cose_number(-43i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        HashAlgorithmId::Sha512 => {
            <C::HashProvider as embedded_cal::HashProvider>::Algorithm::from_cose_number(-44i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn map_hmac_alg<C: Cal>(
    alg: HmacAlgorithmId,
) -> Result<<C::HmacProvider as embedded_cal::HmacProvider>::Algorithm, CryptoError> {
    match alg {
        HmacAlgorithmId::HmacSha256 => {
            <C::HmacProvider as embedded_cal::HmacProvider>::Algorithm::from_cose_number(5i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        HmacAlgorithmId::HmacSha384 => {
            <C::HmacProvider as embedded_cal::HmacProvider>::Algorithm::from_cose_number(6i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        HmacAlgorithmId::HmacSha512 => {
            <C::HmacProvider as embedded_cal::HmacProvider>::Algorithm::from_cose_number(7i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}

fn map_dh_alg<C: Cal>(
    alg: DhAlgorithmId,
) -> Result<<C::DhProvider as embedded_cal::DhProvider>::Algorithm, CryptoError> {
    match alg {
        DhAlgorithmId::EcdhP256 => {
            <C::DhProvider as embedded_cal::DhProvider>::Algorithm::from_cose_ecdh(1i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        DhAlgorithmId::EcdhP384 => {
            <C::DhProvider as embedded_cal::DhProvider>::Algorithm::from_cose_ecdh(2i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        DhAlgorithmId::X25519 => {
            <C::DhProvider as embedded_cal::DhProvider>::Algorithm::from_cose_ecdh(4i8)
                .ok_or(CryptoError::UnsupportedAlgorithm)
        }
        _ => Err(CryptoError::UnsupportedAlgorithm),
    }
}
