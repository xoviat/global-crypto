#![no_std]

pub mod error;
pub mod types;
pub mod driver;
pub mod registry;
pub mod sync_api;
pub mod async_api;

pub use error::CryptoError;
pub use types::*;
pub use driver::CryptoDriver;
pub use registry::{register_provider, ProviderEntry};
