//! Hash and HMAC operations.
//!
//! Every type is a RustCrypto trait wrapper backed by the corresponding
//! `embassy-crypto` type, which is served at link time by whichever driver
//! is registered for it (a HAL, a software driver crate, ...). The same
//! code is therefore hardware-accelerated when a hardware driver is linked
//! in, without any changes here.

// ===========================================================================
// Digest macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_digest {
    (
        $name:ident,
        $backend:path,
        $size:ty,
        $block_size:ty,
        $alg_name:expr
    ) => {
        /// RustCrypto `Digest` implementation backed by the corresponding `embassy-crypto` type.
        #[derive(Clone)]
        pub struct $name {
            inner: $backend,
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self {
                    inner: <$backend>::new(),
                }
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::digest::OutputSizeUser for $name {
            type OutputSize = $size;
        }

        impl ::digest::Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }
        }

        impl ::digest::FixedOutput for $name {
            #[inline]
            fn finalize_into(self, out: &mut ::digest::Output<Self>) {
                out.as_mut_slice().copy_from_slice(&self.inner.finalize());
            }
        }

        impl ::digest::Reset for $name {
            #[inline]
            fn reset(&mut self) {
                *self = Self::default();
            }
        }

        impl ::digest::FixedOutputReset for $name {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut ::digest::Output<Self>) {
                <Self as ::digest::FixedOutput>::finalize_into(self.clone(), out);
                <Self as ::digest::Reset>::reset(self);
            }
        }

        impl ::digest::HashMarker for $name {}

        impl ::cipher::BlockSizeUser for $name {
            type BlockSize = $block_size;
        }

        impl ::crypto_common::AlgorithmName for $name {
            fn write_alg_name(f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str($alg_name)
            }
        }
    };
}

// ===========================================================================
// HMAC macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_hmac {
    (
        $name:ident,
        $backend:path,
        $key_size:ty,
        $out_size:ty
    ) => {
        /// RustCrypto `Mac` implementation backed by the corresponding `embassy-crypto` type.
        #[derive(Clone)]
        pub struct $name {
            inner: $backend,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::digest::OutputSizeUser for $name {
            type OutputSize = $out_size;
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::KeyInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>) -> Self {
                Self {
                    inner: <$backend>::new(key.as_slice()),
                }
            }

            #[inline]
            fn new_from_slice(key: &[u8]) -> Result<Self, ::digest::InvalidLength> {
                Ok(Self {
                    inner: <$backend>::new(key),
                })
            }
        }

        impl ::digest::Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }
        }

        impl ::digest::FixedOutput for $name {
            #[inline]
            fn finalize_into(self, out: &mut ::digest::Output<Self>) {
                out.as_mut_slice().copy_from_slice(&self.inner.finalize());
            }
        }

        impl ::digest::MacMarker for $name {}
    };
}

// ===========================================================================
// Digests
// ===========================================================================

impl_digest!(Md5, embassy_crypto::Md5, ::generic_array::typenum::U16, ::generic_array::typenum::U64, "MD5");
impl_digest!(Sha1, embassy_crypto::Sha1, ::generic_array::typenum::U20, ::generic_array::typenum::U64, "SHA-1");
impl_digest!(Sha224, embassy_crypto::Sha224, ::generic_array::typenum::U28, ::generic_array::typenum::U64, "SHA-224");
impl_digest!(Sha256, embassy_crypto::Sha256, ::generic_array::typenum::U32, ::generic_array::typenum::U64, "SHA-256");
impl_digest!(Sha384, embassy_crypto::Sha384, ::generic_array::typenum::U48, ::generic_array::typenum::U128, "SHA-384");
impl_digest!(Sha512_224, embassy_crypto::Sha512_224, ::generic_array::typenum::U28, ::generic_array::typenum::U128, "SHA-512/224");
impl_digest!(Sha512_256, embassy_crypto::Sha512_256, ::generic_array::typenum::U32, ::generic_array::typenum::U128, "SHA-512/256");
impl_digest!(Sha512, embassy_crypto::Sha512, ::generic_array::typenum::U64, ::generic_array::typenum::U128, "SHA-512");

// ===========================================================================
// HMACs
// ===========================================================================

impl_hmac!(HmacSha1, embassy_crypto::HmacSha1, ::generic_array::typenum::U64, ::generic_array::typenum::U20);
impl_hmac!(HmacSha224, embassy_crypto::HmacSha224, ::generic_array::typenum::U64, ::generic_array::typenum::U28);
impl_hmac!(HmacSha256, embassy_crypto::HmacSha256, ::generic_array::typenum::U64, ::generic_array::typenum::U32);
impl_hmac!(HmacSha384, embassy_crypto::HmacSha384, ::generic_array::typenum::U128, ::generic_array::typenum::U48);
impl_hmac!(HmacSha512_224, embassy_crypto::HmacSha512_224, ::generic_array::typenum::U128, ::generic_array::typenum::U28);
impl_hmac!(HmacSha512_256, embassy_crypto::HmacSha512_256, ::generic_array::typenum::U128, ::generic_array::typenum::U32);
impl_hmac!(HmacSha512, embassy_crypto::HmacSha512, ::generic_array::typenum::U128, ::generic_array::typenum::U64);
