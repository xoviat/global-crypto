//! Global provider registry with cached capability bitmasks.
//!
//! Providers are registered once at startup and selected automatically
//! based on capability and priority. A pre-computed `u16` capability mask
//! per provider allows ultra-fast bitwise rejection before any virtual
//! dispatch occurs.

use crate::driver::{CryptoDriver, CAP_AEAD, CAP_CORDIC, CAP_DH, CAP_HASH, CAP_HKDF, CAP_HMAC};
use crate::types::{
    AeadAlgorithmId, CordicAlgorithmId, DhAlgorithmId, HashAlgorithmId, HmacAlgorithmId,
};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Maximum number of registered providers.
pub const MAX_PROVIDERS: usize = 8;

/// An entry in the provider registry.
#[derive(Clone, Copy)]
pub struct ProviderEntry {
    /// The driver implementation.
    pub driver: &'static dyn CryptoDriver,
    /// Priority: lower values are preferred.
    pub priority: i32,
}

/// Internal slot combining the entry with its cached capability mask.
#[derive(Clone, Copy)]
struct RegistrySlot {
    entry: ProviderEntry,
    caps: u16,
}

/// Wrapper that makes `UnsafeCell` `Sync` because we guarantee single-writer
/// (during init, under critical section) / multi-reader (after init) access.
struct SyncUnsafeCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for SyncUnsafeCell<T> {}

static REGISTRY: SyncUnsafeCell<[Option<RegistrySlot>; MAX_PROVIDERS]> =
    SyncUnsafeCell(UnsafeCell::new([None; MAX_PROVIDERS]));
static REGISTRY_LEN: AtomicUsize = AtomicUsize::new(0);

// ------------------------------------------------------------------
// Capability probing
// ------------------------------------------------------------------

/// Probe a driver for all known capabilities.
///
/// If the driver natively reports capabilities (non-zero), that value is
/// used directly. Otherwise we fall back to calling `supports_*` for each
/// algorithm category.
fn probe_capabilities(driver: &dyn CryptoDriver) -> u16 {
    let native = driver.capabilities();
    if native != 0 {
        return native;
    }

    let mut cap = 0u16;

    // Probe AEAD
    for alg in [
        AeadAlgorithmId::AesCcm16_64_128,
        AeadAlgorithmId::AesCcm16_128_128,
        AeadAlgorithmId::Aes128Gcm,
        AeadAlgorithmId::Aes256Gcm,
    ] {
        if driver.supports_aead(alg) {
            cap |= CAP_AEAD;
            break;
        }
    }

    // Probe Hash
    for alg in [
        HashAlgorithmId::Sha256,
        HashAlgorithmId::Sha384,
        HashAlgorithmId::Sha512,
    ] {
        if driver.supports_hash(alg) {
            cap |= CAP_HASH;
            break;
        }
    }

    // Probe HMAC
    for alg in [
        HmacAlgorithmId::HmacSha256,
        HmacAlgorithmId::HmacSha384,
        HmacAlgorithmId::HmacSha512,
    ] {
        if driver.supports_hmac(alg) {
            cap |= CAP_HMAC;
            break;
        }
    }

    // Probe DH
    for alg in [
        DhAlgorithmId::EcdhP256,
        DhAlgorithmId::EcdhP384,
        DhAlgorithmId::X25519,
    ] {
        if driver.supports_dh(alg) {
            cap |= CAP_DH;
            break;
        }
    }

    // Probe HKDF (re-uses HMAC algorithm IDs)
    for alg in [
        HmacAlgorithmId::HmacSha256,
        HmacAlgorithmId::HmacSha384,
        HmacAlgorithmId::HmacSha512,
    ] {
        if driver.supports_hkdf(alg) {
            cap |= CAP_HKDF;
            break;
        }
    }

    // Probe CORDIC
    for alg in [
        CordicAlgorithmId::SinCos,
        CordicAlgorithmId::Atan2,
        CordicAlgorithmId::Hypot,
    ] {
        if driver.supports_cordic(alg) {
            cap |= CAP_CORDIC;
            break;
        }
    }

    cap
}

// ------------------------------------------------------------------
// Registration
// ------------------------------------------------------------------

/// Register a cryptographic provider globally.
///
/// # Safety
/// This must be called before any crypto operations, typically during
/// system initialization. It must not be called concurrently.
pub fn register_provider(entry: ProviderEntry) {
    critical_section::with(|_| {
        let len = REGISTRY_LEN.load(Ordering::Relaxed);
        if len >= MAX_PROVIDERS {
            // Silently ignore if registry is full.
            return;
        }

        let caps = probe_capabilities(entry.driver);

        // SAFETY: we are inside a critical section, so exclusive access is guaranteed.
        let slots = unsafe { &mut *REGISTRY.0.get() };
        slots[len] = Some(RegistrySlot { entry, caps });

        // Insertion sort by priority (MAX_PROVIDERS is tiny, so this is fast).
        for i in (1..=len).rev() {
            let a = slots[i].unwrap();
            let b = slots[i - 1].unwrap();
            if a.entry.priority < b.entry.priority {
                slots.swap(i, i - 1);
            } else {
                break;
            }
        }

        REGISTRY_LEN.store(len + 1, Ordering::Release);
    });
}

// ------------------------------------------------------------------
// Selection
// ------------------------------------------------------------------

/// Select the highest-priority provider that satisfies the given capability
/// predicate.
///
/// The `required_cap` bitmask is checked first via a cheap bitwise `&`.
/// Only providers whose cached mask contains the required bit proceed to
/// the (slower) `capability` closure, which typically performs a virtual
/// dispatch to `supports_*` for a specific algorithm ID.
#[inline]
pub(crate) fn select_provider<F>(
    required_cap: u16,
    capability: F,
) -> Option<&'static dyn CryptoDriver>
where
    F: Fn(&dyn CryptoDriver) -> bool,
{
    // No critical section needed for reads: registration happens before use,
    // and the atomic len with Acquire ordering ensures we see all writes.
    let len = REGISTRY_LEN.load(Ordering::Acquire);

    // SAFETY: after init, no writer races with us. Before init, the user has
    // violated the safety contract of `register_provider`.
    let slots = unsafe { &*REGISTRY.0.get() };

    for i in 0..len {
        // SAFETY: slots[i] is guaranteed initialized for i < len.
        let slot = unsafe { slots.get_unchecked(i).unwrap() };

        // Ultra-fast bitwise rejection: skip provider if it doesn't have the
        // required capability category.
        if (slot.caps & required_cap) == 0 {
            continue;
        }

        if capability(slot.entry.driver) {
            return Some(slot.entry.driver);
        }
    }
    None
}
