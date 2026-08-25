#![no_std]

pub use embassy_crypto_driver::{
    Algorithm, BlockingOp, ContextHandle, CryptoError, HashContext,
};

// ------------------------------------------------------------------
// Blocking dispatch
// ------------------------------------------------------------------

/// Dispatch a blocking operation to the linked crypto driver.
pub fn dispatch_blocking(op: BlockingOp<'_>) -> Result<(), CryptoError> {
    match embassy_crypto_driver::dispatch_blocking(op) {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(e),
        None => Err(CryptoError::Unsupported),
    }
}

// ------------------------------------------------------------------
// Hash types
// ------------------------------------------------------------------

macro_rules! define_hash {
    ($(#[$meta:meta])* $name:ident, $algo:path, $out:expr) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            handle: ContextHandle,
        }

        impl $name {
            /// Create a new hash context.
            pub fn new() -> Result<Self, CryptoError> {
                let handle = embassy_crypto_driver::try_context_init($algo)?;
                Ok(Self { handle })
            }

            /// Feed more data into the hash.
            pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                embassy_crypto_driver::try_context_update(self.handle, data)
            }

            /// Reset the hash to its initial state.
            pub fn reset(&mut self) -> Result<(), CryptoError> {
                embassy_crypto_driver::try_context_reset(self.handle)
            }

            /// Finalize the hash and write the digest into `out`.
            ///
            /// `out` must be at least [`$name::output_size`] bytes long.
            pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
                embassy_crypto_driver::try_context_finalize(self.handle, out)
            }

            /// Digest length in bytes.
            pub const fn output_size() -> usize {
                $out
            }
        }
    };
}

define_hash!(Sha1, Algorithm::SHA1, 20);
define_hash!(Md5, Algorithm::MD5, 16);
define_hash!(Sha224, Algorithm::SHA224, 28);
define_hash!(Sha256, Algorithm::SHA256, 32);
define_hash!(Sha384, Algorithm::SHA384, 48);
define_hash!(Sha512_224, Algorithm::SHA512_224, 28);
define_hash!(Sha512_256, Algorithm::SHA512_256, 32);
define_hash!(Sha512, Algorithm::SHA512, 64);

// ------------------------------------------------------------------
// HMAC types
// ------------------------------------------------------------------

macro_rules! define_hmac {
    ($(#[$meta:meta])* $name:ident, $hash:ident, $algo:ident, $out:expr, $block:expr) => {
        const _: () = {
            #[cfg(feature = "software-hmac")]
            #[derive(Clone)]
            enum Inner {
                Driver(ContextHandle),
                Software {
                    hash: $hash,
                    key_opad: [u8; $block],
                },
            }

            $(#[$meta])*
            #[derive(Clone)]
            pub struct $name {
                #[cfg(not(feature = "software-hmac"))]
                handle: ContextHandle,
                #[cfg(feature = "software-hmac")]
                inner: Inner,
            }

            impl $name {
                /// Create a new HMAC context with the given key.
                ///
                /// Tries the driver's native HMAC first. If the driver reports
                /// `Unsupported`, falls back to a software HMAC built on top
                /// of the driver's hash acceleration (requires the `software-hmac`
                /// feature).
                pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
                    // Try driver-native HMAC.
                    match embassy_crypto_driver::try_context_init(Algorithm::$algo { key }) {
                        Ok(handle) => {
                            #[cfg(not(feature = "software-hmac"))]
                            return Ok(Self { handle });
                            #[cfg(feature = "software-hmac")]
                            return Ok(Self { inner: Inner::Driver(handle) });
                        }
                        Err(CryptoError::Unsupported) => {}
                        Err(e) => return Err(e),
                    }

                    #[cfg(feature = "software-hmac")]
                    {
                        // Fallback: software HMAC using driver-accelerated hash.
                        let mut hash = $hash::new()?;
                        let mut key_padded = [0u8; $block];

                        if key.len() > $block {
                            // Hash the key first, then pad the digest.
                            hash.update(key)?;
                            let mut key_hash = [0u8; $out];
                            hash.finalize_into(&mut key_hash)?;
                            key_padded[..$out].copy_from_slice(&key_hash);
                            hash = $hash::new()?;
                        } else {
                            key_padded[..key.len()].copy_from_slice(key);
                        }

                        let mut key_ipad = key_padded;
                        for b in &mut key_ipad {
                            *b ^= 0x36;
                        }
                        let mut key_opad = key_padded;
                        for b in &mut key_opad {
                            *b ^= 0x5C;
                        }

                        hash.update(&key_ipad)?;

                        Ok(Self {
                            inner: Inner::Software { hash, key_opad },
                        })
                    }

                    #[cfg(not(feature = "software-hmac"))]
                    Err(CryptoError::Unsupported)
                }

                /// Feed more data into the HMAC.
                pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                    #[cfg(not(feature = "software-hmac"))]
                    {
                        embassy_crypto_driver::try_context_update(self.handle, data)
                    }
                    #[cfg(feature = "software-hmac")]
                    {
                        match &mut self.inner {
                            Inner::Driver(handle) => {
                                embassy_crypto_driver::try_context_update(*handle, data)
                            }
                            Inner::Software { hash, .. } => hash.update(data),
                        }
                    }
                }

                /// Finalize the HMAC and write the tag into `out`.
                ///
                /// `out` must be at least [`$name::output_size`] bytes long.
                pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
                    #[cfg(not(feature = "software-hmac"))]
                    {
                        embassy_crypto_driver::try_context_finalize(self.handle, out)
                    }
                    #[cfg(feature = "software-hmac")]
                    {
                        match self.inner {
                            Inner::Driver(handle) => {
                                embassy_crypto_driver::try_context_finalize(handle, out)
                            }
                            Inner::Software { hash, key_opad } => {
                                let mut inner = [0u8; $out];
                                hash.finalize_into(&mut inner)?;
                                let mut outer = $hash::new()?;
                                outer.update(&key_opad)?;
                                outer.update(&inner)?;
                                outer.finalize_into(out)
                            }
                        }
                    }
                }

                /// Tag length in bytes.
                pub const fn output_size() -> usize {
                    $out
                }
            }
        };
    };
}

define_hmac!(HmacSha256, Sha256, HmacSha256, 32, 64);
define_hmac!(HmacSha384, Sha384, HmacSha384, 48, 128);
define_hmac!(HmacSha512, Sha512, HmacSha512, 64, 128);
