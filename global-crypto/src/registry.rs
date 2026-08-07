//! Global provider registry.
//!
//! Providers are registered once at startup and selected automatically
//! based on capability and priority.

use crate::driver::CryptoDriver;
use core::cell::RefCell;
use critical_section::Mutex;
use heapless::Vec;

/// Maximum number of registered providers.
pub const MAX_PROVIDERS: usize = 4;

/// An entry in the provider registry.
pub struct ProviderEntry {
    /// The driver implementation.
    pub driver: &'static dyn CryptoDriver,
    /// Priority: lower values are preferred.
    pub priority: i32,
}

static REGISTRY: Mutex<RefCell<Vec<ProviderEntry, MAX_PROVIDERS>>> =
    Mutex::new(RefCell::new(Vec::new()));

/// Register a cryptographic provider globally.
///
/// # Safety
/// This must be called before any crypto operations, typically during
/// system initialization. It must not be called concurrently.
pub fn register_provider(entry: ProviderEntry) {
    critical_section::with(|cs| {
        let mut providers = REGISTRY.borrow(cs).borrow_mut();
        // Silently ignore if registry is full. In production you may want to panic.
        let _ = providers.push(entry);
        providers.sort_by_key(|e| e.priority);
    });
}

/// Internal helper: select the highest-priority provider that satisfies
/// the given capability predicate.
pub(crate) fn select_provider<F>(capability: F) -> Option<&'static dyn CryptoDriver>
where
    F: Fn(&dyn CryptoDriver) -> bool,
{
    critical_section::with(|cs| {
        let providers = REGISTRY.borrow(cs).borrow();
        providers
            .iter()
            .find(|e| capability(e.driver))
            .map(|e| e.driver)
    })
}
