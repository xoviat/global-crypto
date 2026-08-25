#![no_std]

pub use embassy_crypto_driver::{Algorithm, BlockingOp, ContextHandle, CryptoError, HashContext};

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
    ($(#[$meta:meta])* $name:ident, $algo:path, $out:expr, $soft_ty:ty, $soft_new:expr) => {
        #[allow(dead_code)]
        const _: () = {
            #[derive(Clone)]
            enum Inner {
                Driver(ContextHandle),
                #[cfg(feature = "software-hash")]
                RustCrypto($soft_ty),
            }

            $(#[$meta])*
            #[derive(Clone)]
            #[allow(dead_code)]
            pub struct $name {
                inner: Inner,
            }

            #[allow(dead_code)]
            impl $name {
                /// Create a new hash context.
                ///
                /// Tries the linked driver first. If the driver reports
                /// `Unsupported`, falls back to a pure software implementation
                /// (requires the `software-hash` feature).
                pub fn new() -> Result<Self, CryptoError> {
                    match embassy_crypto_driver::try_context_init($algo) {
                        Ok(handle) => {
                            return Ok(Self { inner: Inner::Driver(handle) });
                        }
                        Err(CryptoError::Unsupported) => {}
                        Err(e) => return Err(e),
                    }

                    #[cfg(feature = "software-hash")]
                    {
                        Ok(Self {
                            inner: Inner::RustCrypto($soft_new),
                        })
                    }

                    #[cfg(not(feature = "software-hash"))]
                    Err(CryptoError::Unsupported)
                }

                /// Feed more data into the hash.
                pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                    match &mut self.inner {
                        Inner::Driver(handle) => {
                            embassy_crypto_driver::try_context_update(*handle, data)
                        }
                        #[cfg(feature = "software-hash")]
                        Inner::RustCrypto(hash) => {
                            digest::Digest::update(hash, data);
                            Ok(())
                        }
                    }
                }

                /// Reset the hash to its initial state.
                pub fn reset(&mut self) -> Result<(), CryptoError> {
                    match &mut self.inner {
                        Inner::Driver(handle) => {
                            embassy_crypto_driver::try_context_reset(*handle)
                        }
                        #[cfg(feature = "software-hash")]
                        Inner::RustCrypto(hash) => {
                            *hash = $soft_new;
                            Ok(())
                        }
                    }
                }

                /// Finalize the hash and write the digest into `out`.
                ///
                /// `out` must be at least [`$name::output_size`] bytes long.
                pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
                    match self.inner {
                        Inner::Driver(handle) => {
                            embassy_crypto_driver::try_context_finalize(handle, out)
                        }
                        #[cfg(feature = "software-hash")]
                        Inner::RustCrypto(hash) => {
                            let result = digest::Digest::finalize(hash);
                            out[..$out].copy_from_slice(&result);
                            Ok(())
                        }
                    }
                }

                /// Digest length in bytes.
                pub const fn output_size() -> usize {
                    $out
                }
            }
        };
    };
}

define_hash!(Sha1, Algorithm::SHA1, 20, sha1::Sha1, sha1::Sha1::new());
define_hash!(Md5, Algorithm::MD5, 16, md5::Md5, md5::Md5::new());
define_hash!(
    Sha224,
    Algorithm::SHA224,
    28,
    sha2::Sha224,
    sha2::Sha224::new()
);
define_hash!(
    Sha256,
    Algorithm::SHA256,
    32,
    sha2::Sha256,
    sha2::Sha256::new()
);
define_hash!(
    Sha384,
    Algorithm::SHA384,
    48,
    sha2::Sha384,
    sha2::Sha384::new()
);
define_hash!(
    Sha512_224,
    Algorithm::SHA512_224,
    28,
    sha2::Sha512_224,
    sha2::Sha512_224::new()
);
define_hash!(
    Sha512_256,
    Algorithm::SHA512_256,
    32,
    sha2::Sha512_256,
    sha2::Sha512_256::new()
);
define_hash!(
    Sha512,
    Algorithm::SHA512,
    64,
    sha2::Sha512,
    sha2::Sha512::new()
);

// ------------------------------------------------------------------
// HMAC types
// ------------------------------------------------------------------

macro_rules! define_hmac {
    ($(#[$meta:meta])* $name:ident, $hash:ident, $soft_hash:path, $algo:ident, $out:expr, $block:expr) => {
        #[allow(dead_code)]
        const _: () = {
            #[derive(Clone)]
            enum Inner {
                Driver(ContextHandle),
                #[cfg(feature = "software-hmac")]
                Software {
                    hash: $hash,
                    key_opad: [u8; $block],
                },
                #[cfg(feature = "software-hash")]
                RustCrypto(hmac::Hmac<$soft_hash>),
            }

            $(#[$meta])*
            #[derive(Clone)]
            #[allow(dead_code)]
            pub struct $name {
                inner: Inner,
            }

            #[allow(dead_code)]
            impl $name {
                /// Create a new HMAC context with the given key.
                ///
                /// Tries the driver's native HMAC first. If the driver reports
                /// `Unsupported`, falls back to a software HMAC built on top
                /// of the driver's hash acceleration (requires the `software-hmac`
                /// feature). If that also fails, falls back to a pure software
                /// implementation (requires the `software-hash` feature).
                pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
                    // 1. Try driver-native HMAC.
                    match embassy_crypto_driver::try_context_init(Algorithm::$algo { key }) {
                        Ok(handle) => {
                            return Ok(Self { inner: Inner::Driver(handle) });
                        }
                        Err(CryptoError::Unsupported) => {}
                        Err(e) => return Err(e),
                    }

                    // 2. Try software HMAC using driver-accelerated hash.
                    #[cfg(feature = "software-hmac")]
                    {
                        match Self::new_software(key) {
                            Ok(s) => return Ok(s),
                            Err(CryptoError::Unsupported) => {}
                            Err(e) => return Err(e),
                        }
                    }

                    // 3. Try pure software HMAC.
                    #[cfg(feature = "software-hash")]
                    {
                        let mac = hmac::Hmac::<$soft_hash>::new_from_slice(key)
                            .map_err(|_| CryptoError::InvalidKey)?;
                        return Ok(Self {
                            inner: Inner::RustCrypto(mac),
                        });
                    }

                    Err(CryptoError::Unsupported)
                }

                /// Feed more data into the HMAC.
                pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
                    match &mut self.inner {
                        Inner::Driver(handle) => {
                            embassy_crypto_driver::try_context_update(*handle, data)
                        }
                        #[cfg(feature = "software-hmac")]
                        Inner::Software { hash, .. } => hash.update(data),
                        #[cfg(feature = "software-hash")]
                        Inner::RustCrypto(mac) => {
                            hmac::Mac::update(mac, data);
                            Ok(())
                        }
                    }
                }

                /// Finalize the HMAC and write the tag into `out`.
                ///
                /// `out` must be at least [`$name::output_size`] bytes long.
                pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
                    match self.inner {
                        Inner::Driver(handle) => {
                            embassy_crypto_driver::try_context_finalize(handle, out)
                        }
                        #[cfg(feature = "software-hmac")]
                        Inner::Software { hash, key_opad } => {
                            let mut inner = [0u8; $out];
                            hash.finalize_into(&mut inner)?;
                            let mut outer = $hash::new()?;
                            outer.update(&key_opad)?;
                            outer.update(&inner)?;
                            outer.finalize_into(out)
                        }
                        #[cfg(feature = "software-hash")]
                        Inner::RustCrypto(mac) => {
                            let result = hmac::Mac::finalize(mac);
                            out[..$out].copy_from_slice(&result.into_bytes());
                            Ok(())
                        }
                    }
                }

                /// Tag length in bytes.
                pub const fn output_size() -> usize {
                    $out
                }

                #[cfg(feature = "software-hmac")]
                fn new_software(key: &[u8]) -> Result<Self, CryptoError> {
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
            }
        };
    };
}

define_hmac!(HmacSha256, Sha256, sha2::Sha256, HmacSha256, 32, 64);
define_hmac!(HmacSha384, Sha384, sha2::Sha384, HmacSha384, 48, 128);
define_hmac!(HmacSha512, Sha512, sha2::Sha512, HmacSha512, 64, 128);
