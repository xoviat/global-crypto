//! Basic usage example.
//!
//! This example uses `embedded_cal::empty::EmptyCal` to demonstrate that
//! the bridge compiles and the global API is callable. Since `EmptyCal`
//! supports no algorithms, all operations return `UnsupportedAlgorithm`.

use embedded_cal::empty::EmptyCal;
use global_crypto::{
    register_provider, AeadKey, AesCcm16_64_128, EcdhP256, HmacSha256, Nonce, ProviderEntry,
    Sha256, Tag,
};
use global_crypto_embedded_cal::EmbeddedCalBridge;

static BRIDGE: EmbeddedCalBridge<EmptyCal<true>> = EmbeddedCalBridge::new(EmptyCal);

fn main() {
    // Register the provider at startup
    register_provider(ProviderEntry {
        driver: &BRIDGE,
        priority: 0,
    });

    // --- AEAD (will fail because EmptyCal has no algorithms) ---
    let key = AeadKey::<AesCcm16_64_128>::from_bytes(&[0u8; 16]).unwrap();
    let nonce = Nonce::<AesCcm16_64_128>::from_bytes(&[0u8; 13]).unwrap();
    let mut message = [1u8, 2u8, 3u8, 4u8];
    let mut tag = Tag::<AesCcm16_64_128>::from_bytes(&[0u8; 8]).unwrap();

    match global_crypto::sync_api::aead_encrypt(&key, &nonce, &mut message, b"aad", &mut tag) {
        Ok(()) => println!("AEAD encrypt ok"),
        Err(e) => println!("AEAD encrypt failed as expected: {:?}", e),
    }

    // --- Hash ---
    match global_crypto::sync_api::hash::<Sha256>(b"hello") {
        Ok(digest) => println!("Hash ok: {:?}", digest.as_bytes()),
        Err(e) => println!("Hash failed as expected: {:?}", e),
    }

    // --- HMAC ---
    match global_crypto::sync_api::hmac::<HmacSha256>(b"key", b"data") {
        Ok(mac) => println!("HMAC ok: {:?}", mac.as_bytes()),
        Err(e) => println!("HMAC failed as expected: {:?}", e),
    }

    // --- DH ---
    match global_crypto::sync_api::dh_generate_keypair::<EcdhP256>() {
        Ok((pubkey, seckey)) => println!("DH keypair ok"),
        Err(e) => println!("DH keypair failed as expected: {:?}", e),
    }

    // --- HKDF ---
    match global_crypto::sync_api::hkdf_extract::<HmacSha256>(Some(b"salt"), b"ikm") {
        Ok(prk) => println!("HKDF extract ok: {:?}", prk.as_bytes()),
        Err(e) => println!("HKDF extract failed as expected: {:?}", e),
    }
}
