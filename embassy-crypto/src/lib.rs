#![no_std]

pub use embassy_crypto_driver::CryptoError;
pub(crate) use embassy_crypto_driver::{Algorithm, BlockingOp, ContextHandle};

#[cfg(feature = "software-hash")]
use digest::Digest;

// ------------------------------------------------------------------
// Hash types
// ------------------------------------------------------------------

#[derive(Clone)]
pub enum Sha1 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hash")]
    RustCrypto(sha1::Sha1),
}

impl Sha1 {
    pub fn new() -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::SHA1) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hash")]
        { Ok(Self::RustCrypto(Digest::new())) }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { digest::Digest::update(hash, data); Ok(()) }
        }
    }
    pub fn reset(&mut self) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_reset(*handle),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { *hash = Digest::new(); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => {
                let result = digest::Digest::finalize(hash);
                out[..20].copy_from_slice(&result);
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 20 }
}

#[derive(Clone)]
pub enum Md5 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hash")]
    RustCrypto(md5::Md5),
}

impl Md5 {
    pub fn new() -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::MD5) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hash")]
        { Ok(Self::RustCrypto(Digest::new())) }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { digest::Digest::update(hash, data); Ok(()) }
        }
    }
    pub fn reset(&mut self) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_reset(*handle),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { *hash = Digest::new(); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => {
                let result = digest::Digest::finalize(hash);
                out[..16].copy_from_slice(&result);
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 16 }
}

#[derive(Clone)]
pub enum Sha224 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hash")]
    RustCrypto(sha2::Sha224),
}

impl Sha224 {
    pub fn new() -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::SHA224) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hash")]
        { Ok(Self::RustCrypto(Digest::new())) }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { digest::Digest::update(hash, data); Ok(()) }
        }
    }
    pub fn reset(&mut self) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_reset(*handle),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { *hash = Digest::new(); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => {
                let result = digest::Digest::finalize(hash);
                out[..28].copy_from_slice(&result);
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 28 }
}

#[derive(Clone)]
pub enum Sha256 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hash")]
    RustCrypto(sha2::Sha256),
}

impl Sha256 {
    pub fn new() -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::SHA256) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hash")]
        { Ok(Self::RustCrypto(Digest::new())) }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { digest::Digest::update(hash, data); Ok(()) }
        }
    }
    pub fn reset(&mut self) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_reset(*handle),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { *hash = Digest::new(); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => {
                let result = digest::Digest::finalize(hash);
                out[..32].copy_from_slice(&result);
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 32 }
}

#[derive(Clone)]
pub enum Sha384 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hash")]
    RustCrypto(sha2::Sha384),
}

impl Sha384 {
    pub fn new() -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::SHA384) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hash")]
        { Ok(Self::RustCrypto(Digest::new())) }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { digest::Digest::update(hash, data); Ok(()) }
        }
    }
    pub fn reset(&mut self) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_reset(*handle),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { *hash = Digest::new(); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => {
                let result = digest::Digest::finalize(hash);
                out[..48].copy_from_slice(&result);
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 48 }
}

#[derive(Clone)]
pub enum Sha512_224 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hash")]
    RustCrypto(sha2::Sha512_224),
}

impl Sha512_224 {
    pub fn new() -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::SHA512_224) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hash")]
        { Ok(Self::RustCrypto(Digest::new())) }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { digest::Digest::update(hash, data); Ok(()) }
        }
    }
    pub fn reset(&mut self) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_reset(*handle),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { *hash = Digest::new(); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => {
                let result = digest::Digest::finalize(hash);
                out[..28].copy_from_slice(&result);
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 28 }
}

#[derive(Clone)]
pub enum Sha512_256 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hash")]
    RustCrypto(sha2::Sha512_256),
}

impl Sha512_256 {
    pub fn new() -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::SHA512_256) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hash")]
        { Ok(Self::RustCrypto(Digest::new())) }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { digest::Digest::update(hash, data); Ok(()) }
        }
    }
    pub fn reset(&mut self) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_reset(*handle),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { *hash = Digest::new(); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => {
                let result = digest::Digest::finalize(hash);
                out[..32].copy_from_slice(&result);
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 32 }
}

#[derive(Clone)]
pub enum Sha512 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hash")]
    RustCrypto(sha2::Sha512),
}

impl Sha512 {
    pub fn new() -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::SHA512) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hash")]
        { Ok(Self::RustCrypto(Digest::new())) }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { digest::Digest::update(hash, data); Ok(()) }
        }
    }
    pub fn reset(&mut self) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_reset(*handle),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => { *hash = Digest::new(); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(hash) => {
                let result = digest::Digest::finalize(hash);
                out[..64].copy_from_slice(&result);
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 64 }
}

// ------------------------------------------------------------------
// HMAC types
// ------------------------------------------------------------------

#[derive(Clone)]
pub enum HmacSha256 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hmac")]
    Software { hash: Sha256, key_opad: [u8; 64] },
    #[cfg(feature = "software-hash")]
    RustCrypto(hmac::Hmac<sha2::Sha256>),
}

impl HmacSha256 {
    pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::HmacSha256 { key }) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hmac")]
        {
            match Self::new_software(key) {
                Ok(s) => return Ok(s),
                Err(CryptoError::Unsupported) => {}
                Err(e) => return Err(e),
            }
        }
        #[cfg(feature = "software-hash")]
        {
            let mac = <hmac::Hmac<sha2::Sha256> as digest::KeyInit>::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKey)?;
            Ok(Self::RustCrypto(mac))
        }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hmac")]
            Self::Software { hash, .. } => hash.update(data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(mac) => { digest::Mac::update(mac, data); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hmac")]
            Self::Software { hash, key_opad } => {
                let mut inner = [0u8; 32];
                hash.finalize_into(&mut inner)?;
                let mut outer = Sha256::new()?;
                outer.update(&key_opad[..])?;
                outer.update(&inner[..])?;
                outer.finalize_into(out)
            }
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(mac) => {
                let result = digest::Mac::finalize(mac);
                out[..32].copy_from_slice(&result.into_bytes());
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 32 }

    #[cfg(feature = "software-hmac")]
    fn new_software(key: &[u8]) -> Result<Self, CryptoError> {
        let mut hash = Sha256::new()?;
        let mut key_padded = [0u8; 64];
        if key.len() > 64 {
            hash.update(key)?;
            let mut key_hash = [0u8; 32];
            hash.finalize_into(&mut key_hash)?;
            key_padded[..32].copy_from_slice(&key_hash);
            hash = Sha256::new()?;
        } else {
            key_padded[..key.len()].copy_from_slice(key);
        }
        let mut key_ipad = key_padded;
        for b in &mut key_ipad { *b ^= 0x36; }
        let mut key_opad = key_padded;
        for b in &mut key_opad { *b ^= 0x5C; }
        hash.update(&key_ipad)?;
        Ok(Self::Software { hash, key_opad })
    }
}

#[derive(Clone)]
pub enum HmacSha384 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hmac")]
    Software { hash: Sha384, key_opad: [u8; 128] },
    #[cfg(feature = "software-hash")]
    RustCrypto(hmac::Hmac<sha2::Sha384>),
}

impl HmacSha384 {
    pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::HmacSha384 { key }) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hmac")]
        {
            match Self::new_software(key) {
                Ok(s) => return Ok(s),
                Err(CryptoError::Unsupported) => {}
                Err(e) => return Err(e),
            }
        }
        #[cfg(feature = "software-hash")]
        {
            let mac = <hmac::Hmac<sha2::Sha384> as digest::KeyInit>::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKey)?;
            Ok(Self::RustCrypto(mac))
        }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hmac")]
            Self::Software { hash, .. } => hash.update(data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(mac) => { digest::Mac::update(mac, data); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hmac")]
            Self::Software { hash, key_opad } => {
                let mut inner = [0u8; 48];
                hash.finalize_into(&mut inner)?;
                let mut outer = Sha384::new()?;
                outer.update(&key_opad[..])?;
                outer.update(&inner[..])?;
                outer.finalize_into(out)
            }
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(mac) => {
                let result = digest::Mac::finalize(mac);
                out[..48].copy_from_slice(&result.into_bytes());
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 48 }

    #[cfg(feature = "software-hmac")]
    fn new_software(key: &[u8]) -> Result<Self, CryptoError> {
        let mut hash = Sha384::new()?;
        let mut key_padded = [0u8; 128];
        if key.len() > 128 {
            hash.update(key)?;
            let mut key_hash = [0u8; 48];
            hash.finalize_into(&mut key_hash)?;
            key_padded[..48].copy_from_slice(&key_hash);
            hash = Sha384::new()?;
        } else {
            key_padded[..key.len()].copy_from_slice(key);
        }
        let mut key_ipad = key_padded;
        for b in &mut key_ipad { *b ^= 0x36; }
        let mut key_opad = key_padded;
        for b in &mut key_opad { *b ^= 0x5C; }
        hash.update(&key_ipad)?;
        Ok(Self::Software { hash, key_opad })
    }
}

#[derive(Clone)]
pub enum HmacSha512 {
    Driver(ContextHandle),
    #[cfg(feature = "software-hmac")]
    Software { hash: Sha512, key_opad: [u8; 128] },
    #[cfg(feature = "software-hash")]
    RustCrypto(hmac::Hmac<sha2::Sha512>),
}

impl HmacSha512 {
    pub fn new_from_slice(key: &[u8]) -> Result<Self, CryptoError> {
        match embassy_crypto_driver::try_context_init(Algorithm::HmacSha512 { key }) {
            Ok(handle) => return Ok(Self::Driver(handle)),
            Err(CryptoError::Unsupported) => {}
            Err(e) => return Err(e),
        }
        #[cfg(feature = "software-hmac")]
        {
            match Self::new_software(key) {
                Ok(s) => return Ok(s),
                Err(CryptoError::Unsupported) => {}
                Err(e) => return Err(e),
            }
        }
        #[cfg(feature = "software-hash")]
        {
            let mac = <hmac::Hmac<sha2::Sha512> as digest::KeyInit>::new_from_slice(key)
                .map_err(|_| CryptoError::InvalidKey)?;
            Ok(Self::RustCrypto(mac))
        }
        #[cfg(not(feature = "software-hash"))]
        { Err(CryptoError::Unsupported) }
    }
    pub fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_update(*handle, data),
            #[cfg(feature = "software-hmac")]
            Self::Software { hash, .. } => hash.update(data),
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(mac) => { digest::Mac::update(mac, data); Ok(()) }
        }
    }
    pub fn finalize_into(self, out: &mut [u8]) -> Result<(), CryptoError> {
        match self {
            Self::Driver(handle) => embassy_crypto_driver::try_context_finalize(handle, out),
            #[cfg(feature = "software-hmac")]
            Self::Software { hash, key_opad } => {
                let mut inner = [0u8; 64];
                hash.finalize_into(&mut inner)?;
                let mut outer = Sha512::new()?;
                outer.update(&key_opad[..])?;
                outer.update(&inner[..])?;
                outer.finalize_into(out)
            }
            #[cfg(feature = "software-hash")]
            Self::RustCrypto(mac) => {
                let result = digest::Mac::finalize(mac);
                out[..64].copy_from_slice(&result.into_bytes());
                Ok(())
            }
        }
    }
    pub const fn output_size() -> usize { 64 }

    #[cfg(feature = "software-hmac")]
    fn new_software(key: &[u8]) -> Result<Self, CryptoError> {
        let mut hash = Sha512::new()?;
        let mut key_padded = [0u8; 128];
        if key.len() > 128 {
            hash.update(key)?;
            let mut key_hash = [0u8; 64];
            hash.finalize_into(&mut key_hash)?;
            key_padded[..64].copy_from_slice(&key_hash);
            hash = Sha512::new()?;
        } else {
            key_padded[..key.len()].copy_from_slice(key);
        }
        let mut key_ipad = key_padded;
        for b in &mut key_ipad { *b ^= 0x36; }
        let mut key_opad = key_padded;
        for b in &mut key_opad { *b ^= 0x5C; }
        hash.update(&key_ipad)?;
        Ok(Self::Software { hash, key_opad })
    }
}

// ------------------------------------------------------------------
// AEAD types
// ------------------------------------------------------------------

/// AES-128-GCM in-place AEAD.
#[derive(Clone)]
pub struct AesGcm128 {
    key: [u8; 16],
}

impl AesGcm128 {
    /// Create a new AES-128-GCM instance from a 16-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKey);
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }

    /// Encrypt `buffer` in-place and write the 16-byte authentication tag into `tag`.
    pub fn encrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        let mut tag_buf = [0u8; 16];
        let ptr = buffer.as_mut_ptr();
        let len = buffer.len();
        let plaintext = unsafe { core::slice::from_raw_parts(ptr, len) };
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::AesGcm128Encrypt {
            key: &self.key,
            nonce,
            aad,
            plaintext,
            ciphertext: buffer,
            tag: &mut tag_buf,
        }) {
            Some(Ok(())) => {
                tag.copy_from_slice(&tag_buf);
                Ok(())
            }
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }

    /// Decrypt `buffer` in-place and verify the 16-byte authentication tag.
    pub fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        let tag_buf = *tag;
        let ptr = buffer.as_mut_ptr();
        let len = buffer.len();
        let ciphertext = unsafe { core::slice::from_raw_parts(ptr, len) };
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::AesGcm128Decrypt {
            key: &self.key,
            nonce,
            aad,
            ciphertext,
            plaintext: buffer,
            tag: &tag_buf,
        }) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }
}

/// AES-256-GCM in-place AEAD.
#[derive(Clone)]
pub struct AesGcm256 {
    key: [u8; 32],
}

impl AesGcm256 {
    /// Create a new AES-256-GCM instance from a 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }

    /// Encrypt `buffer` in-place and write the 16-byte authentication tag into `tag`.
    pub fn encrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        let mut tag_buf = [0u8; 16];
        let ptr = buffer.as_mut_ptr();
        let len = buffer.len();
        let plaintext = unsafe { core::slice::from_raw_parts(ptr, len) };
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::AesGcm256Encrypt {
            key: &self.key,
            nonce,
            aad,
            plaintext,
            ciphertext: buffer,
            tag: &mut tag_buf,
        }) {
            Some(Ok(())) => {
                tag.copy_from_slice(&tag_buf);
                Ok(())
            }
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }

    /// Decrypt `buffer` in-place and verify the 16-byte authentication tag.
    pub fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        let tag_buf = *tag;
        let ptr = buffer.as_mut_ptr();
        let len = buffer.len();
        let ciphertext = unsafe { core::slice::from_raw_parts(ptr, len) };
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::AesGcm256Decrypt {
            key: &self.key,
            nonce,
            aad,
            ciphertext,
            plaintext: buffer,
            tag: &tag_buf,
        }) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }
}

// ------------------------------------------------------------------
// AES-128-ECB
// ------------------------------------------------------------------

/// AES-128-ECB block cipher.
///
/// Operates on single 16-byte blocks.  No padding is performed by this
/// wrapper — the caller must supply exactly one block.
#[derive(Clone)]
pub struct Aes128Ecb {
    key: [u8; 16],
}

impl Aes128Ecb {
    /// Create a new AES-128-ECB instance from a 16-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKey);
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }

    /// Encrypt a single 16-byte block in-place.
    pub fn encrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), CryptoError> {
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::Aes128EcbEncrypt {
            block,
            key: &self.key,
        }) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }

    /// Decrypt a single 16-byte block in-place.
    pub fn decrypt_block(&mut self, block: &mut [u8; 16]) -> Result<(), CryptoError> {
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::Aes128EcbDecrypt {
            block,
            key: &self.key,
        }) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }
}

// ------------------------------------------------------------------
// AES-128-CMAC
// ------------------------------------------------------------------

/// AES-128-CMAC message authentication code.
#[derive(Clone)]
pub struct Aes128Cmac {
    key: [u8; 16],
}

impl Aes128Cmac {
    /// Create a new AES-128-CMAC instance from a 16-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKey);
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }

    /// Compute the CMAC tag for `data` and write the 16-byte result into `out`.
    pub fn generate(&mut self, data: &[u8], out: &mut [u8; 16]) -> Result<(), CryptoError> {
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::Aes128Cmac {
            key: &self.key,
            data,
            out,
        }) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }
}

// ------------------------------------------------------------------
// AES-CCM-128 (16-byte tag)
// ------------------------------------------------------------------

/// AES-128-CCM in-place AEAD with a 16-byte authentication tag.
#[derive(Clone)]
pub struct AesCcm128 {
    key: [u8; 16],
}

impl AesCcm128 {
    /// Create a new AES-128-CCM instance from a 16-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKey);
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }

    /// Encrypt `buffer` in-place and write the 16-byte tag into `tag`.
    pub fn encrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8; 16],
    ) -> Result<(), CryptoError> {
        let ptr = buffer.as_mut_ptr();
        let len = buffer.len();
        let plaintext = unsafe { core::slice::from_raw_parts(ptr, len) };
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::AesCcm128Encrypt {
            key: &self.key,
            nonce,
            aad,
            plaintext,
            ciphertext: buffer,
            tag,
        }) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }

    /// Decrypt `buffer` in-place and verify the 16-byte tag.
    pub fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        let ptr = buffer.as_mut_ptr();
        let len = buffer.len();
        let ciphertext = unsafe { core::slice::from_raw_parts(ptr, len) };
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::AesCcm128Decrypt {
            key: &self.key,
            nonce,
            aad,
            ciphertext,
            plaintext: buffer,
            tag,
        }) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }
}

// ------------------------------------------------------------------
// AES-CCM8-128 (8-byte tag)
// ------------------------------------------------------------------

/// AES-128-CCM in-place AEAD with an 8-byte authentication tag.
#[derive(Clone)]
pub struct AesCcm8_128 {
    key: [u8; 16],
}

impl AesCcm8_128 {
    /// Create a new AES-128-CCM-8 instance from a 16-byte key.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != 16 {
            return Err(CryptoError::InvalidKey);
        }
        let mut k = [0u8; 16];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }

    /// Encrypt `buffer` in-place and write the 8-byte tag into `tag`.
    pub fn encrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &mut [u8; 8],
    ) -> Result<(), CryptoError> {
        let ptr = buffer.as_mut_ptr();
        let len = buffer.len();
        let plaintext = unsafe { core::slice::from_raw_parts(ptr, len) };
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::AesCcm8_128Encrypt {
            key: &self.key,
            nonce,
            aad,
            plaintext,
            ciphertext: buffer,
            tag,
        }) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }

    /// Decrypt `buffer` in-place and verify the 8-byte tag.
    pub fn decrypt_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), CryptoError> {
        let ptr = buffer.as_mut_ptr();
        let len = buffer.len();
        let ciphertext = unsafe { core::slice::from_raw_parts(ptr, len) };
        match embassy_crypto_driver::dispatch_blocking(BlockingOp::AesCcm8_128Decrypt {
            key: &self.key,
            nonce,
            aad,
            ciphertext,
            plaintext: buffer,
            tag,
        }) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(e),
            None => Err(CryptoError::Unsupported),
        }
    }
}
