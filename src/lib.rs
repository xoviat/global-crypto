#![no_std]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

#[cfg(feature = "ec")]
pub mod ec;

#[cfg(feature = "p256")]
pub mod p256;

#[cfg(feature = "p384")]
pub mod p384;

mod aes;
mod hash;

pub use aes::*;
pub use hash::*;
