//! AES operations.
//!
//! Every type is a RustCrypto trait wrapper (block cipher, block mode,
//! stream cipher, AEAD or MAC) backed by the corresponding `embassy-crypto`
//! type, which is served at link time by whichever driver is registered for
//! it. Modes keep the layering: the mode types are built on the
//! [`Aes128`]/[`Aes256`] block ciphers, so a lower layer that is accelerated
//! (hardware ECB, say) accelerates the modes too.

// ===========================================================================
// ECB block-cipher macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_ecb {
    (
        $name:ident,
        $backend:path,
        $key_size:ty
    ) => {
        /// RustCrypto `BlockCipherEncrypt`/`BlockCipherDecrypt` implementation backed by the corresponding `embassy-crypto` type.
        #[derive(Clone)]
        pub struct $name {
            inner: $backend,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::cipher::BlockSizeUser for $name {
            type BlockSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::ParBlocksSizeUser for $name {
            type ParBlocksSize = ::generic_array::typenum::U1;
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::KeyInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>) -> Self {
                Self {
                    inner: <$backend>::new(key.as_slice().try_into().unwrap()),
                }
            }
        }

        impl ::cipher::BlockCipherEncBackend for $name {
            #[inline]
            fn encrypt_block(&self, block: ::cipher::InOut<'_, '_, ::cipher::Block<Self>>) {
                let (in_ptr, out_ptr) = block.into_raw();
                let (in_ptr, out_ptr) = (in_ptr as *const u8, out_ptr as *mut u8);
                unsafe {
                    if core::ptr::eq(in_ptr, out_ptr) {
                        self.inner
                            .encrypt_blocks(core::slice::from_raw_parts_mut(out_ptr, 16))
                            .unwrap();
                    } else {
                        self.inner
                            .encrypt_blocks_to(
                                core::slice::from_raw_parts(in_ptr, 16),
                                core::slice::from_raw_parts_mut(out_ptr, 16),
                            )
                            .unwrap();
                    }
                }
            }
        }

        impl ::cipher::BlockCipherEncrypt for $name {
            #[inline]
            fn encrypt_with_backend(&self, f: impl ::cipher::BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
                f.call(self);
            }

            #[inline]
            fn encrypt_blocks(&self, blocks: &mut [::cipher::Block<Self>]) {
                if blocks.is_empty() {
                    return;
                }
                let out_ptr = blocks.as_mut_ptr() as *mut u8;
                self.inner
                    .encrypt_blocks(unsafe {
                        core::slice::from_raw_parts_mut(out_ptr, blocks.len() * 16)
                    })
                    .unwrap();
            }

            #[inline]
            fn encrypt_blocks_inout(&self, blocks: ::cipher::inout::InOutBuf<'_, '_, ::cipher::Block<Self>>) {
                if blocks.is_empty() {
                    return;
                }
                let len = blocks.len() * 16;
                let (in_ptr, out_ptr) = blocks.into_raw();
                let (in_ptr, out_ptr) = (in_ptr as *const u8, out_ptr as *mut u8);
                unsafe {
                    if core::ptr::eq(in_ptr, out_ptr) {
                        self.inner
                            .encrypt_blocks(core::slice::from_raw_parts_mut(out_ptr, len))
                            .unwrap();
                    } else {
                        self.inner
                            .encrypt_blocks_to(
                                core::slice::from_raw_parts(in_ptr, len),
                                core::slice::from_raw_parts_mut(out_ptr, len),
                            )
                            .unwrap();
                    }
                }
            }
        }

        impl ::cipher::BlockCipherDecBackend for $name {
            #[inline]
            fn decrypt_block(&self, block: ::cipher::InOut<'_, '_, ::cipher::Block<Self>>) {
                let (in_ptr, out_ptr) = block.into_raw();
                let (in_ptr, out_ptr) = (in_ptr as *const u8, out_ptr as *mut u8);
                unsafe {
                    if core::ptr::eq(in_ptr, out_ptr) {
                        self.inner
                            .decrypt_blocks(core::slice::from_raw_parts_mut(out_ptr, 16))
                            .unwrap();
                    } else {
                        self.inner
                            .decrypt_blocks_to(
                                core::slice::from_raw_parts(in_ptr, 16),
                                core::slice::from_raw_parts_mut(out_ptr, 16),
                            )
                            .unwrap();
                    }
                }
            }
        }

        impl ::cipher::BlockCipherDecrypt for $name {
            #[inline]
            fn decrypt_with_backend(&self, f: impl ::cipher::BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
                f.call(self);
            }

            #[inline]
            fn decrypt_blocks(&self, blocks: &mut [::cipher::Block<Self>]) {
                if blocks.is_empty() {
                    return;
                }
                let out_ptr = blocks.as_mut_ptr() as *mut u8;
                self.inner
                    .decrypt_blocks(unsafe {
                        core::slice::from_raw_parts_mut(out_ptr, blocks.len() * 16)
                    })
                    .unwrap();
            }

            #[inline]
            fn decrypt_blocks_inout(&self, blocks: ::cipher::inout::InOutBuf<'_, '_, ::cipher::Block<Self>>) {
                if blocks.is_empty() {
                    return;
                }
                let len = blocks.len() * 16;
                let (in_ptr, out_ptr) = blocks.into_raw();
                let (in_ptr, out_ptr) = (in_ptr as *const u8, out_ptr as *mut u8);
                unsafe {
                    if core::ptr::eq(in_ptr, out_ptr) {
                        self.inner
                            .decrypt_blocks(core::slice::from_raw_parts_mut(out_ptr, len))
                            .unwrap();
                    } else {
                        self.inner
                            .decrypt_blocks_to(
                                core::slice::from_raw_parts(in_ptr, len),
                                core::slice::from_raw_parts_mut(out_ptr, len),
                            )
                            .unwrap();
                    }
                }
            }
        }
    };
}

// ===========================================================================
// CBC block-cipher macros
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_cbc_enc {
    (
        $name:ident,
        $backend:path,
        $key_size:ty
    ) => {
        /// RustCrypto `BlockModeEncrypt` implementation backed by the corresponding `embassy-crypto` type.
        pub struct $name {
            inner: $backend,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::cipher::BlockSizeUser for $name {
            type BlockSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::ParBlocksSizeUser for $name {
            type ParBlocksSize = ::generic_array::typenum::U1;
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::IvSizeUser for $name {
            type IvSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::KeyIvInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>, iv: &::cipher::Iv<Self>) -> Self {
                Self {
                    inner: <$backend>::new(
                        key.as_slice().try_into().unwrap(),
                        iv.as_slice().try_into().unwrap(),
                    ),
                }
            }
        }

        impl ::cipher::BlockModeEncBackend for $name {
            #[inline]
            fn encrypt_block(&mut self, block: ::cipher::InOut<'_, '_, ::cipher::Block<Self>>) {
                let (in_ptr, out_ptr) = block.into_raw();
                let (in_ptr, out_ptr) = (in_ptr as *const u8, out_ptr as *mut u8);
                unsafe {
                    if core::ptr::eq(in_ptr, out_ptr) {
                        self.inner
                            .encrypt(core::slice::from_raw_parts_mut(out_ptr, 16))
                            .unwrap();
                    } else {
                        self.inner
                            .encrypt_to(
                                core::slice::from_raw_parts(in_ptr, 16),
                                core::slice::from_raw_parts_mut(out_ptr, 16),
                            )
                            .unwrap();
                    }
                }
            }
        }

        impl ::cipher::BlockModeEncrypt for $name {
            #[inline]
            fn encrypt_with_backend(&mut self, f: impl ::cipher::BlockModeEncClosure<BlockSize = Self::BlockSize>) {
                f.call(self);
            }

            #[inline]
            fn encrypt_blocks(&mut self, blocks: &mut [::cipher::Block<Self>]) {
                if blocks.is_empty() {
                    return;
                }
                let out_ptr = blocks.as_mut_ptr() as *mut u8;
                self.inner
                    .encrypt(unsafe {
                        core::slice::from_raw_parts_mut(out_ptr, blocks.len() * 16)
                    })
                    .unwrap();
            }
        }
    };
}

#[allow(unused_macros)]
macro_rules! impl_cbc_dec {
    (
        $name:ident,
        $backend:path,
        $key_size:ty
    ) => {
        /// RustCrypto `BlockModeDecrypt` implementation backed by the corresponding `embassy-crypto` type.
        pub struct $name {
            inner: $backend,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::cipher::BlockSizeUser for $name {
            type BlockSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::ParBlocksSizeUser for $name {
            type ParBlocksSize = ::generic_array::typenum::U1;
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::IvSizeUser for $name {
            type IvSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::KeyIvInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>, iv: &::cipher::Iv<Self>) -> Self {
                Self {
                    inner: <$backend>::new(
                        key.as_slice().try_into().unwrap(),
                        iv.as_slice().try_into().unwrap(),
                    ),
                }
            }
        }

        impl ::cipher::BlockModeDecBackend for $name {
            #[inline]
            fn decrypt_block(&mut self, block: ::cipher::InOut<'_, '_, ::cipher::Block<Self>>) {
                let (in_ptr, out_ptr) = block.into_raw();
                let (in_ptr, out_ptr) = (in_ptr as *const u8, out_ptr as *mut u8);
                unsafe {
                    if core::ptr::eq(in_ptr, out_ptr) {
                        self.inner
                            .decrypt(core::slice::from_raw_parts_mut(out_ptr, 16))
                            .unwrap();
                    } else {
                        self.inner
                            .decrypt_to(
                                core::slice::from_raw_parts(in_ptr, 16),
                                core::slice::from_raw_parts_mut(out_ptr, 16),
                            )
                            .unwrap();
                    }
                }
            }
        }

        impl ::cipher::BlockModeDecrypt for $name {
            #[inline]
            fn decrypt_with_backend(&mut self, f: impl ::cipher::BlockModeDecClosure<BlockSize = Self::BlockSize>) {
                f.call(self);
            }

            #[inline]
            fn decrypt_blocks(&mut self, blocks: &mut [::cipher::Block<Self>]) {
                if blocks.is_empty() {
                    return;
                }
                let out_ptr = blocks.as_mut_ptr() as *mut u8;
                self.inner
                    .decrypt(unsafe {
                        core::slice::from_raw_parts_mut(out_ptr, blocks.len() * 16)
                    })
                    .unwrap();
            }
        }
    };
}

// ===========================================================================
// GCM AEAD macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_gcm {
    (
        $name:ident,
        $backend:path,
        $key_size:ty
    ) => {
        /// RustCrypto `AeadInPlace` implementation backed by the corresponding `embassy-crypto` type.
        pub struct $name {
            inner: $backend,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::KeyInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>) -> Self {
                Self {
                    inner: <$backend>::new(key.as_slice().try_into().unwrap()),
                }
            }
        }

        impl ::aead::AeadCore for $name {
            type NonceSize = ::generic_array::typenum::U12;
            type TagSize = ::generic_array::typenum::U16;
            const TAG_POSITION: ::aead::TagPosition = ::aead::TagPosition::Postfix;
        }

        impl ::aead::AeadInOut for $name {
            fn encrypt_inout_detached(
                &self,
                nonce: &::aead::Nonce<Self>,
                associated_data: &[u8],
                buffer: ::aead::inout::InOutBuf<'_, '_, u8>,
            ) -> Result<::aead::Tag<Self>, ::aead::Error> {
                let len = buffer.len();
                let (in_ptr, out_ptr) = buffer.into_raw();
                let nonce: &[u8; 12] = nonce.as_slice().try_into().map_err(|_| ::aead::Error)?;
                let tag = unsafe {
                    if core::ptr::eq(in_ptr, out_ptr) {
                        self.inner.encrypt(
                            nonce,
                            associated_data,
                            core::slice::from_raw_parts_mut(out_ptr, len),
                        )
                    } else {
                        self.inner.encrypt_to(
                            nonce,
                            associated_data,
                            core::slice::from_raw_parts(in_ptr, len),
                            core::slice::from_raw_parts_mut(out_ptr, len),
                        )
                    }
                }
                .map_err(|_| ::aead::Error)?;
                let mut tag_out = ::aead::Tag::<Self>::default();
                tag_out.copy_from_slice(&tag);
                Ok(tag_out)
            }

            fn decrypt_inout_detached(
                &self,
                nonce: &::aead::Nonce<Self>,
                associated_data: &[u8],
                buffer: ::aead::inout::InOutBuf<'_, '_, u8>,
                tag: &::aead::Tag<Self>,
            ) -> Result<(), ::aead::Error> {
                let len = buffer.len();
                let (in_ptr, out_ptr) = buffer.into_raw();
                let nonce: &[u8; 12] = nonce.as_slice().try_into().map_err(|_| ::aead::Error)?;
                let tag: &[u8; 16] = tag.as_slice().try_into().map_err(|_| ::aead::Error)?;
                unsafe {
                    if core::ptr::eq(in_ptr, out_ptr) {
                        self.inner.decrypt(
                            nonce,
                            associated_data,
                            core::slice::from_raw_parts_mut(out_ptr, len),
                            tag,
                        )
                    } else {
                        self.inner.decrypt_to(
                            nonce,
                            associated_data,
                            core::slice::from_raw_parts(in_ptr, len),
                            core::slice::from_raw_parts_mut(out_ptr, len),
                            tag,
                        )
                    }
                }
                .map_err(|_| ::aead::Error)
            }
        }
    };
}

// ===========================================================================
// CTR stream-cipher macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_ctr {
    (
        $name:ident,
        $backend:path,
        $key_size:ty
    ) => {
        /// RustCrypto `StreamCipher` implementation backed by the corresponding `embassy-crypto` type.
        ///
        /// Uses AES-CTR mode with a 128-bit big-endian counter (NIST SP 800-38A).
        /// Encryption and decryption are the same operation.
        pub struct $name {
            inner: $backend,
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::IvSizeUser for $name {
            type IvSize = ::generic_array::typenum::U16;
        }

        impl ::cipher::KeyIvInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>, iv: &::cipher::Iv<Self>) -> Self {
                Self {
                    inner: <$backend>::new(
                        key.as_slice().try_into().unwrap(),
                        iv.as_slice().try_into().unwrap(),
                    ),
                }
            }
        }

        impl ::cipher::StreamCipher for $name {
            #[inline]
            fn check_remaining(&self, _data_len: usize) -> Result<(), ::cipher::StreamCipherError> {
                // AES-CTR with a 128-bit counter has 2^128 blocks = 2^132 bytes
                // of keystream before repetition. For any practical embedded
                // buffer this is effectively infinite.
                Ok(())
            }

            #[inline]
            fn unchecked_apply_keystream_inout(&mut self, buf: ::cipher::inout::InOutBuf<'_, '_, u8>) {
                let len = buf.len();
                let (in_ptr, out_ptr) = buf.into_raw();
                unsafe {
                    if core::ptr::eq(in_ptr, out_ptr) {
                        self.inner
                            .apply_keystream(core::slice::from_raw_parts_mut(out_ptr, len));
                    } else {
                        self.inner
                            .apply_keystream_to(
                                core::slice::from_raw_parts(in_ptr, len),
                                core::slice::from_raw_parts_mut(out_ptr, len),
                            )
                            .unwrap();
                    }
                }
            }

            #[inline]
            fn unchecked_write_keystream(&mut self, buf: &mut [u8]) {
                buf.fill(0);
                self.inner.apply_keystream(buf);
            }
        }
    };
}

// ===========================================================================
// CMAC macro
// ===========================================================================

#[allow(unused_macros)]
macro_rules! impl_cmac {
    (
        $name:ident,
        $backend:path,
        $key_size:ty
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
            type OutputSize = ::generic_array::typenum::U16;
        }

        impl ::crypto_common::KeySizeUser for $name {
            type KeySize = $key_size;
        }

        impl ::cipher::KeyInit for $name {
            #[inline]
            fn new(key: &::digest::Key<Self>) -> Self {
                Self {
                    inner: <$backend>::new(key.as_slice().try_into().unwrap()),
                }
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

        impl ::digest::Reset for $name {
            #[inline]
            fn reset(&mut self) {
                self.inner.reset();
            }
        }

        impl ::digest::FixedOutputReset for $name {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut ::digest::Output<Self>) {
                <Self as ::digest::FixedOutput>::finalize_into(self.clone(), out);
                <Self as ::digest::Reset>::reset(self);
            }
        }

        impl ::digest::MacMarker for $name {}
    };
}

// ===========================================================================
// ECB
// ===========================================================================

impl_ecb!(Aes128, embassy_crypto::Aes128, ::generic_array::typenum::U16);
impl_ecb!(Aes256, embassy_crypto::Aes256, ::generic_array::typenum::U32);

// ===========================================================================
// CBC
// ===========================================================================

impl_cbc_enc!(Aes128CbcEncrypt, embassy_crypto::Aes128CbcEncrypt, ::generic_array::typenum::U16);
impl_cbc_dec!(Aes128CbcDecrypt, embassy_crypto::Aes128CbcDecrypt, ::generic_array::typenum::U16);
impl_cbc_enc!(Aes256CbcEncrypt, embassy_crypto::Aes256CbcEncrypt, ::generic_array::typenum::U32);
impl_cbc_dec!(Aes256CbcDecrypt, embassy_crypto::Aes256CbcDecrypt, ::generic_array::typenum::U32);

// ===========================================================================
// GCM
// ===========================================================================

impl_gcm!(Aes128Gcm, embassy_crypto::Aes128Gcm, ::generic_array::typenum::U16);
impl_gcm!(Aes256Gcm, embassy_crypto::Aes256Gcm, ::generic_array::typenum::U32);

// ===========================================================================
// CCM
// ===========================================================================

macro_rules! impl_ccm_module {
    ($mod_name:ident, $type_name:ident, $backend:path, $key_size:ident) => {
        mod $mod_name {
            use ::aead::common::array::ArraySize;
            use ::aead::inout::InOutBuf;
            use ::aead::{AeadCore, AeadInOut, TagPosition};
            use ::cipher::KeyInit;
            use ::crypto_common::KeySizeUser;
            use ::digest::Key;
            use ::generic_array::typenum::$key_size as KeySizeT;

            /// RustCrypto `AeadInOut` implementation for AES-CCM, backed by the corresponding `embassy-crypto` type.
            ///
            /// Generic over `TagSize` (4, 6, 8, 10, 12, 14 or 16) and `NonceSize` (7-13).
            pub struct $type_name<TagSize, NonceSize> {
                inner: $backend,
                _phantom: core::marker::PhantomData<(TagSize, NonceSize)>,
            }

            impl<TagSize, NonceSize> Clone for $type_name<TagSize, NonceSize> {
                fn clone(&self) -> Self {
                    Self {
                        inner: self.inner.clone(),
                        _phantom: core::marker::PhantomData,
                    }
                }
            }

            impl<TagSize, NonceSize> core::fmt::Debug for $type_name<TagSize, NonceSize> {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.debug_struct(stringify!($type_name)).finish_non_exhaustive()
                }
            }

            impl<TagSize, NonceSize> KeySizeUser for $type_name<TagSize, NonceSize> {
                type KeySize = KeySizeT;
            }

            impl<TagSize, NonceSize> KeyInit for $type_name<TagSize, NonceSize> {
                fn new(key: &Key<Self>) -> Self {
                    Self {
                        inner: <$backend>::new(key.as_slice().try_into().unwrap()),
                        _phantom: core::marker::PhantomData,
                    }
                }
            }

            impl<TagSize, NonceSize> AeadCore for $type_name<TagSize, NonceSize>
            where
                TagSize: ArraySize,
                NonceSize: ArraySize,
            {
                type NonceSize = NonceSize;
                type TagSize = TagSize;
                const TAG_POSITION: TagPosition = TagPosition::Postfix;
            }

            impl<TagSize, NonceSize> AeadInOut for $type_name<TagSize, NonceSize>
            where
                TagSize: ArraySize,
                NonceSize: ArraySize,
            {
                fn encrypt_inout_detached(
                    &self,
                    nonce: &::aead::Nonce<Self>,
                    associated_data: &[u8],
                    buffer: InOutBuf<'_, '_, u8>,
                ) -> Result<::aead::Tag<Self>, ::aead::Error> {
                    let len = buffer.len();
                    let (in_ptr, out_ptr) = buffer.into_raw();
                    let mut tag = ::aead::Tag::<Self>::default();
                    unsafe {
                        if core::ptr::eq(in_ptr, out_ptr) {
                            self.inner.encrypt(
                                nonce.as_slice(),
                                associated_data,
                                core::slice::from_raw_parts_mut(out_ptr, len),
                                tag.as_mut_slice(),
                            )
                        } else {
                            self.inner.encrypt_to(
                                nonce.as_slice(),
                                associated_data,
                                core::slice::from_raw_parts(in_ptr, len),
                                core::slice::from_raw_parts_mut(out_ptr, len),
                                tag.as_mut_slice(),
                            )
                        }
                    }
                    .map_err(|_| ::aead::Error)?;
                    Ok(tag)
                }

                fn decrypt_inout_detached(
                    &self,
                    nonce: &::aead::Nonce<Self>,
                    associated_data: &[u8],
                    buffer: InOutBuf<'_, '_, u8>,
                    tag: &::aead::Tag<Self>,
                ) -> Result<(), ::aead::Error> {
                    let len = buffer.len();
                    let (in_ptr, out_ptr) = buffer.into_raw();
                    unsafe {
                        if core::ptr::eq(in_ptr, out_ptr) {
                            self.inner.decrypt(
                                nonce.as_slice(),
                                associated_data,
                                core::slice::from_raw_parts_mut(out_ptr, len),
                                tag.as_slice(),
                            )
                        } else {
                            self.inner.decrypt_to(
                                nonce.as_slice(),
                                associated_data,
                                core::slice::from_raw_parts(in_ptr, len),
                                core::slice::from_raw_parts_mut(out_ptr, len),
                                tag.as_slice(),
                            )
                        }
                    }
                    .map_err(|_| ::aead::Error)
                }
            }
        }

        pub use $mod_name::$type_name;
    };
}

impl_ccm_module!(aes128ccm, Aes128Ccm, embassy_crypto::Aes128Ccm, U16);
impl_ccm_module!(aes256ccm, Aes256Ccm, embassy_crypto::Aes256Ccm, U32);

// ===========================================================================
// CTR
// ===========================================================================

impl_ctr!(Aes128Ctr, embassy_crypto::Aes128Ctr, ::generic_array::typenum::U16);
impl_ctr!(Aes256Ctr, embassy_crypto::Aes256Ctr, ::generic_array::typenum::U32);

// ===========================================================================
// CMAC
// ===========================================================================

impl_cmac!(Aes128Cmac, embassy_crypto::Aes128Cmac, ::generic_array::typenum::U16);
impl_cmac!(Aes256Cmac, embassy_crypto::Aes256Cmac, ::generic_array::typenum::U32);
