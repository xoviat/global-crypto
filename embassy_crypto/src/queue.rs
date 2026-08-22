use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll};
use embassy_sync::waitqueue::AtomicWaker;

use embassy_crypto_driver::{Capabilities, CryptoDriver, CryptoError, Sha256Context};

const STATE_FREE: u8 = 0;
const STATE_PENDING: u8 = 1;
const STATE_RUNNING: u8 = 2;
const STATE_COMPLETE: u8 = 3;
const STATE_CANCELLED: u8 = 4;

const CTX_STATE_FREE: u8 = 0;
const CTX_STATE_INIT: u8 = 1;
const CTX_STATE_BUSY: u8 = 2;

/// Result of an async operation, discriminating between unit and size outputs.
#[derive(Clone, Copy, Debug)]
pub enum OpOutput {
    Unit(Result<(), CryptoError>),
    Size(Result<usize, CryptoError>),
}

impl OpOutput {
    /// Convert to a unit result, treating size errors as unit errors.
    pub fn into_unit(self) -> Result<(), CryptoError> {
        match self {
            OpOutput::Unit(r) => r,
            OpOutput::Size(Err(e)) => Err(e),
            OpOutput::Size(Ok(_)) => Err(CryptoError::HardwareError),
        }
    }

    /// Convert to a size result, treating unit errors as size errors.
    pub fn into_size(self) -> Result<usize, CryptoError> {
        match self {
            OpOutput::Size(r) => r,
            OpOutput::Unit(Err(e)) => Err(e),
            OpOutput::Unit(Ok(())) => Err(CryptoError::HardwareError),
        }
    }
}

/// Opaque handle to an in-flight operation in the `OpTable`.
#[derive(Clone, Copy)]
pub struct OpHandle {
    pub(crate) idx: usize,
}

/// Opaque handle to a SHA-256 streaming context.
#[derive(Clone, Copy)]
pub struct ContextHandle {
    pub(crate) idx: usize,
}

/// Discriminated union of all async operations the runner can schedule.
#[derive(Clone, Copy)]
pub enum OpKind {
    AesGcm128Encrypt {
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        plaintext: *const [u8],
        ciphertext: *mut [u8],
        tag: *mut [u8; 16],
    },
    AesGcm128Decrypt {
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        ciphertext: *const [u8],
        plaintext: *mut [u8],
        tag: *const [u8; 16],
    },
    AesGcm256Encrypt {
        key: *const [u8; 32],
        nonce: *const [u8],
        aad: *const [u8],
        plaintext: *const [u8],
        ciphertext: *mut [u8],
        tag: *mut [u8; 16],
    },
    AesGcm256Decrypt {
        key: *const [u8; 32],
        nonce: *const [u8],
        aad: *const [u8],
        ciphertext: *const [u8],
        plaintext: *mut [u8],
        tag: *const [u8; 16],
    },
    AesCcm128Encrypt {
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        plaintext: *const [u8],
        ciphertext: *mut [u8],
        tag: *mut [u8; 16],
    },
    AesCcm128Decrypt {
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        ciphertext: *const [u8],
        plaintext: *mut [u8],
        tag: *const [u8; 16],
    },
    AesCcm8_128Encrypt {
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        plaintext: *const [u8],
        ciphertext: *mut [u8],
        tag: *mut [u8; 8],
    },
    AesCcm8_128Decrypt {
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        ciphertext: *const [u8],
        plaintext: *mut [u8],
        tag: *const [u8; 8],
    },
    Sha256 {
        data: *const [u8],
        out: *mut [u8; 32],
    },
    Sha384 {
        data: *const [u8],
        out: *mut [u8; 48],
    },
    P256Keygen {
        secret_key: *mut [u8; 32],
        public_key: *mut [u8; 64],
    },
    P256Ecdh {
        secret_key: *const [u8; 32],
        public_key: *const [u8; 64],
        shared_secret: *mut [u8; 32],
    },
    P256EcdsaSign {
        secret_key: *const [u8; 32],
        digest: *const [u8; 32],
        signature: *mut [u8; 64],
    },
    P256EcdsaVerify {
        public_key: *const [u8; 64],
        digest: *const [u8; 32],
        signature: *const [u8; 64],
    },
    P384Keygen {
        secret_key: *mut [u8; 48],
        public_key: *mut [u8; 96],
    },
    P384Ecdh {
        secret_key: *const [u8; 48],
        public_key: *const [u8; 96],
        shared_secret: *mut [u8; 48],
    },
    P384EcdsaSign {
        secret_key: *const [u8; 48],
        digest: *const [u8; 48],
        signature: *mut [u8; 96],
    },
    P384EcdsaVerify {
        public_key: *const [u8; 96],
        digest: *const [u8; 48],
        signature: *const [u8; 96],
    },
    RsaSignPkcs1v15Sha256 {
        private_key: *const [u8],
        digest: *const [u8; 32],
        signature: *mut [u8],
    },
    RsaVerifyPkcs1v15Sha256 {
        public_key: *const [u8],
        digest: *const [u8; 32],
        signature: *const [u8],
    },
    RsaSignPkcs1v15Sha384 {
        private_key: *const [u8],
        digest: *const [u8; 48],
        signature: *mut [u8],
    },
    RsaVerifyPkcs1v15Sha384 {
        public_key: *const [u8],
        digest: *const [u8; 48],
        signature: *const [u8],
    },
    RsaSignPkcs1v15Sha512 {
        private_key: *const [u8],
        digest: *const [u8; 64],
        signature: *mut [u8],
    },
    RsaVerifyPkcs1v15Sha512 {
        public_key: *const [u8],
        digest: *const [u8; 64],
        signature: *const [u8],
    },
    RsaSignPssSha256 {
        private_key: *const [u8],
        digest: *const [u8; 32],
        signature: *mut [u8],
    },
    RsaVerifyPssSha256 {
        public_key: *const [u8],
        digest: *const [u8; 32],
        signature: *const [u8],
    },
    RsaSignPssSha384 {
        private_key: *const [u8],
        digest: *const [u8; 48],
        signature: *mut [u8],
    },
    RsaVerifyPssSha384 {
        public_key: *const [u8],
        digest: *const [u8; 48],
        signature: *const [u8],
    },
    RsaSignPssSha512 {
        private_key: *const [u8],
        digest: *const [u8; 64],
        signature: *mut [u8],
    },
    RsaVerifyPssSha512 {
        public_key: *const [u8],
        digest: *const [u8; 64],
        signature: *const [u8],
    },
    /// Streaming SHA-256 update.
    Sha256Update {
        ctx_handle: ContextHandle,
        data: *const [u8],
    },
    /// Streaming SHA-256 finalize.
    Sha256Finalize {
        ctx_handle: ContextHandle,
        out: *mut [u8; 32],
    },
}

unsafe impl Sync for OpKind {}

impl OpKind {
    /// Which capability is required to execute this operation?
    pub fn required_caps(&self) -> Capabilities {
        match self {
            Self::AesGcm128Encrypt { .. } | Self::AesGcm128Decrypt { .. } => {
                Capabilities::AES_128_GCM
            }
            Self::AesGcm256Encrypt { .. } | Self::AesGcm256Decrypt { .. } => {
                Capabilities::AES_256_GCM
            }
            Self::AesCcm128Encrypt { .. } | Self::AesCcm128Decrypt { .. } => {
                Capabilities::AES_128_CCM
            }
            Self::AesCcm8_128Encrypt { .. } | Self::AesCcm8_128Decrypt { .. } => {
                Capabilities::AES_128_CCM8
            }
            Self::Sha256 { .. } | Self::Sha256Update { .. } | Self::Sha256Finalize { .. } => {
                Capabilities::SHA_256
            }
            Self::Sha384 { .. } => Capabilities::SHA_384,
            Self::P256Keygen { .. } => Capabilities::P256_KEYGEN,
            Self::P256Ecdh { .. } => Capabilities::P256_ECDH,
            Self::P256EcdsaSign { .. } => Capabilities::P256_ECDSA_SIGN,
            Self::P256EcdsaVerify { .. } => Capabilities::P256_ECDSA_VERIFY,
            Self::P384Keygen { .. } => Capabilities::P384_KEYGEN,
            Self::P384Ecdh { .. } => Capabilities::P384_ECDH,
            Self::P384EcdsaSign { .. } => Capabilities::P384_ECDSA_SIGN,
            Self::P384EcdsaVerify { .. } => Capabilities::P384_ECDSA_VERIFY,
            Self::RsaSignPkcs1v15Sha256 { .. } | Self::RsaVerifyPkcs1v15Sha256 { .. } => {
                Capabilities::RSA_PKCS1V15_SHA256
            }
            Self::RsaSignPkcs1v15Sha384 { .. } | Self::RsaVerifyPkcs1v15Sha384 { .. } => {
                Capabilities::RSA_PKCS1V15_SHA384
            }
            Self::RsaSignPkcs1v15Sha512 { .. } | Self::RsaVerifyPkcs1v15Sha512 { .. } => {
                Capabilities::RSA_PKCS1V15_SHA512
            }
            Self::RsaSignPssSha256 { .. } | Self::RsaVerifyPssSha256 { .. } => {
                Capabilities::RSA_PSS_SHA256
            }
            Self::RsaSignPssSha384 { .. } | Self::RsaVerifyPssSha384 { .. } => {
                Capabilities::RSA_PSS_SHA384
            }
            Self::RsaSignPssSha512 { .. } | Self::RsaVerifyPssSha512 { .. } => {
                Capabilities::RSA_PSS_SHA512
            }
        }
    }

    /// Return an error output appropriate for this operation kind.
    pub fn cancelled_output(&self) -> OpOutput {
        match self {
            Self::RsaSignPkcs1v15Sha256 { .. }
            | Self::RsaSignPkcs1v15Sha384 { .. }
            | Self::RsaSignPkcs1v15Sha512 { .. }
            | Self::RsaSignPssSha256 { .. }
            | Self::RsaSignPssSha384 { .. }
            | Self::RsaSignPssSha512 { .. } => OpOutput::Size(Err(CryptoError::HardwareError)),
            _ => OpOutput::Unit(Err(CryptoError::HardwareError)),
        }
    }

    /// True if this operation requires a bound streaming context.
    pub fn is_streaming(&self) -> bool {
        matches!(
            self,
            Self::Sha256Update { .. } | Self::Sha256Finalize { .. }
        )
    }

    /// Extract the context handle from a streaming operation.
    ///
    /// # Panics
    /// Panics if `is_streaming()` is false.
    pub fn ctx_handle(&self) -> ContextHandle {
        match self {
            Self::Sha256Update { ctx_handle, .. } => *ctx_handle,
            Self::Sha256Finalize { ctx_handle, .. } => *ctx_handle,
            _ => panic!("not a streaming operation"),
        }
    }

    /// Execute this operation on the given driver.
    ///
    /// # Safety
    /// All raw pointers stored in this `OpKind` must be valid and unaliased
    /// for the duration of the async call.
    ///
    /// # Panics
    /// Panics for streaming operations (`Sha256Update` / `Sha256Finalize`);
    /// those must be executed by the worker directly.
    pub async unsafe fn execute<D: CryptoDriver>(&self, driver: &mut D) -> OpOutput {
        match self {
            Self::AesGcm128Encrypt {
                key,
                nonce,
                aad,
                plaintext,
                ciphertext,
                tag,
            } => OpOutput::Unit(
                driver
                    .aes_gcm_128_encrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**plaintext },
                        unsafe { &mut **ciphertext },
                        unsafe { &mut **tag },
                    )
                    .await,
            ),
            Self::AesGcm128Decrypt {
                key,
                nonce,
                aad,
                ciphertext,
                plaintext,
                tag,
            } => OpOutput::Unit(
                driver
                    .aes_gcm_128_decrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**ciphertext },
                        unsafe { &mut **plaintext },
                        unsafe { &**tag },
                    )
                    .await,
            ),
            Self::AesGcm256Encrypt {
                key,
                nonce,
                aad,
                plaintext,
                ciphertext,
                tag,
            } => OpOutput::Unit(
                driver
                    .aes_gcm_256_encrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**plaintext },
                        unsafe { &mut **ciphertext },
                        unsafe { &mut **tag },
                    )
                    .await,
            ),
            Self::AesGcm256Decrypt {
                key,
                nonce,
                aad,
                ciphertext,
                plaintext,
                tag,
            } => OpOutput::Unit(
                driver
                    .aes_gcm_256_decrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**ciphertext },
                        unsafe { &mut **plaintext },
                        unsafe { &**tag },
                    )
                    .await,
            ),
            Self::AesCcm128Encrypt {
                key,
                nonce,
                aad,
                plaintext,
                ciphertext,
                tag,
            } => OpOutput::Unit(
                driver
                    .aes_ccm_128_encrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**plaintext },
                        unsafe { &mut **ciphertext },
                        unsafe { &mut **tag },
                    )
                    .await,
            ),
            Self::AesCcm128Decrypt {
                key,
                nonce,
                aad,
                ciphertext,
                plaintext,
                tag,
            } => OpOutput::Unit(
                driver
                    .aes_ccm_128_decrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**ciphertext },
                        unsafe { &mut **plaintext },
                        unsafe { &**tag },
                    )
                    .await,
            ),
            Self::AesCcm8_128Encrypt {
                key,
                nonce,
                aad,
                plaintext,
                ciphertext,
                tag,
            } => OpOutput::Unit(
                driver
                    .aes_ccm8_128_encrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**plaintext },
                        unsafe { &mut **ciphertext },
                        unsafe { &mut **tag },
                    )
                    .await,
            ),
            Self::AesCcm8_128Decrypt {
                key,
                nonce,
                aad,
                ciphertext,
                plaintext,
                tag,
            } => OpOutput::Unit(
                driver
                    .aes_ccm8_128_decrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**ciphertext },
                        unsafe { &mut **plaintext },
                        unsafe { &**tag },
                    )
                    .await,
            ),
            Self::Sha256 { data, out } => OpOutput::Unit(
                driver
                    .sha_256(unsafe { &**data }, unsafe { &mut **out })
                    .await,
            ),
            Self::Sha384 { data, out } => OpOutput::Unit(
                driver
                    .sha_384(unsafe { &**data }, unsafe { &mut **out })
                    .await,
            ),
            Self::P256Keygen {
                secret_key,
                public_key,
            } => OpOutput::Unit(
                driver
                    .p256_keygen(unsafe { &mut **secret_key }, unsafe { &mut **public_key })
                    .await,
            ),
            Self::P256Ecdh {
                secret_key,
                public_key,
                shared_secret,
            } => OpOutput::Unit(
                driver
                    .p256_ecdh(unsafe { &**secret_key }, unsafe { &**public_key }, unsafe {
                        &mut **shared_secret
                    })
                    .await,
            ),
            Self::P256EcdsaSign {
                secret_key,
                digest,
                signature,
            } => OpOutput::Unit(
                driver
                    .p256_ecdsa_sign(unsafe { &**secret_key }, unsafe { &**digest }, unsafe {
                        &mut **signature
                    })
                    .await,
            ),
            Self::P256EcdsaVerify {
                public_key,
                digest,
                signature,
            } => OpOutput::Unit(
                driver
                    .p256_ecdsa_verify(unsafe { &**public_key }, unsafe { &**digest }, unsafe {
                        &**signature
                    })
                    .await,
            ),
            Self::P384Keygen {
                secret_key,
                public_key,
            } => OpOutput::Unit(
                driver
                    .p384_keygen(unsafe { &mut **secret_key }, unsafe { &mut **public_key })
                    .await,
            ),
            Self::P384Ecdh {
                secret_key,
                public_key,
                shared_secret,
            } => OpOutput::Unit(
                driver
                    .p384_ecdh(unsafe { &**secret_key }, unsafe { &**public_key }, unsafe {
                        &mut **shared_secret
                    })
                    .await,
            ),
            Self::P384EcdsaSign {
                secret_key,
                digest,
                signature,
            } => OpOutput::Unit(
                driver
                    .p384_ecdsa_sign(unsafe { &**secret_key }, unsafe { &**digest }, unsafe {
                        &mut **signature
                    })
                    .await,
            ),
            Self::P384EcdsaVerify {
                public_key,
                digest,
                signature,
            } => OpOutput::Unit(
                driver
                    .p384_ecdsa_verify(unsafe { &**public_key }, unsafe { &**digest }, unsafe {
                        &**signature
                    })
                    .await,
            ),
            Self::RsaSignPkcs1v15Sha256 {
                private_key,
                digest,
                signature,
            } => OpOutput::Size(
                driver
                    .rsa_sign_pkcs1v15_sha256(
                        unsafe { &**private_key },
                        unsafe { &**digest },
                        unsafe { &mut **signature },
                    )
                    .await,
            ),
            Self::RsaVerifyPkcs1v15Sha256 {
                public_key,
                digest,
                signature,
            } => OpOutput::Unit(
                driver
                    .rsa_verify_pkcs1v15_sha256(
                        unsafe { &**public_key },
                        unsafe { &**digest },
                        unsafe { &**signature },
                    )
                    .await,
            ),
            Self::RsaSignPkcs1v15Sha384 {
                private_key,
                digest,
                signature,
            } => OpOutput::Size(
                driver
                    .rsa_sign_pkcs1v15_sha384(
                        unsafe { &**private_key },
                        unsafe { &**digest },
                        unsafe { &mut **signature },
                    )
                    .await,
            ),
            Self::RsaVerifyPkcs1v15Sha384 {
                public_key,
                digest,
                signature,
            } => OpOutput::Unit(
                driver
                    .rsa_verify_pkcs1v15_sha384(
                        unsafe { &**public_key },
                        unsafe { &**digest },
                        unsafe { &**signature },
                    )
                    .await,
            ),
            Self::RsaSignPkcs1v15Sha512 {
                private_key,
                digest,
                signature,
            } => OpOutput::Size(
                driver
                    .rsa_sign_pkcs1v15_sha512(
                        unsafe { &**private_key },
                        unsafe { &**digest },
                        unsafe { &mut **signature },
                    )
                    .await,
            ),
            Self::RsaVerifyPkcs1v15Sha512 {
                public_key,
                digest,
                signature,
            } => OpOutput::Unit(
                driver
                    .rsa_verify_pkcs1v15_sha512(
                        unsafe { &**public_key },
                        unsafe { &**digest },
                        unsafe { &**signature },
                    )
                    .await,
            ),
            Self::RsaSignPssSha256 {
                private_key,
                digest,
                signature,
            } => OpOutput::Size(
                driver
                    .rsa_sign_pss_sha256(unsafe { &**private_key }, unsafe { &**digest }, unsafe {
                        &mut **signature
                    })
                    .await,
            ),
            Self::RsaVerifyPssSha256 {
                public_key,
                digest,
                signature,
            } => OpOutput::Unit(
                driver
                    .rsa_verify_pss_sha256(unsafe { &**public_key }, unsafe { &**digest }, unsafe {
                        &**signature
                    })
                    .await,
            ),
            Self::RsaSignPssSha384 {
                private_key,
                digest,
                signature,
            } => OpOutput::Size(
                driver
                    .rsa_sign_pss_sha384(unsafe { &**private_key }, unsafe { &**digest }, unsafe {
                        &mut **signature
                    })
                    .await,
            ),
            Self::RsaVerifyPssSha384 {
                public_key,
                digest,
                signature,
            } => OpOutput::Unit(
                driver
                    .rsa_verify_pss_sha384(unsafe { &**public_key }, unsafe { &**digest }, unsafe {
                        &**signature
                    })
                    .await,
            ),
            Self::RsaSignPssSha512 {
                private_key,
                digest,
                signature,
            } => OpOutput::Size(
                driver
                    .rsa_sign_pss_sha512(unsafe { &**private_key }, unsafe { &**digest }, unsafe {
                        &mut **signature
                    })
                    .await,
            ),
            Self::RsaVerifyPssSha512 {
                public_key,
                digest,
                signature,
            } => OpOutput::Unit(
                driver
                    .rsa_verify_pss_sha512(unsafe { &**public_key }, unsafe { &**digest }, unsafe {
                        &**signature
                    })
                    .await,
            ),
            Self::Sha256Update { .. } | Self::Sha256Finalize { .. } => {
                panic!("streaming ops must be executed by the worker directly")
            }
        }
    }
}

/// One slot in the fixed-size operation table.
pub struct OpSlot {
    state: AtomicU8,
    kind: UnsafeCell<MaybeUninit<OpKind>>,
    result: UnsafeCell<MaybeUninit<OpOutput>>,
    waker: AtomicWaker,
}

// SAFETY: OpSlot is only accessed through OpTable's atomic state machine.
unsafe impl Send for OpSlot {}
unsafe impl Sync for OpSlot {}

impl Default for OpSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl OpSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(STATE_FREE),
            kind: UnsafeCell::new(MaybeUninit::uninit()),
            result: UnsafeCell::new(MaybeUninit::uninit()),
            waker: AtomicWaker::new(),
        }
    }
}

/// Fixed-size slab allocator for in-flight async operations.
///
/// The server allocates a slot, fills it, and hands the index to a worker.
/// The worker transitions the slot through `RUNNING` -> `COMPLETE`.
/// If the server future is dropped early, it may transition `PENDING` -> `CANCELLED`.
pub struct OpTable<const N: usize> {
    slots: [OpSlot; N],
}

impl<const N: usize> Default for OpTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> OpTable<N> {
    /// Create a new operation table.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| OpSlot::new()),
        }
    }

    /// Try to allocate a free slot and store the operation kind.
    pub fn alloc(&self, kind: OpKind) -> Option<OpHandle> {
        for (i, slot) in self.slots.iter().enumerate() {
            if slot
                .state
                .compare_exchange(
                    STATE_FREE,
                    STATE_PENDING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                unsafe {
                    (*slot.kind.get()).write(kind);
                }
                return Some(OpHandle { idx: i });
            }
        }
        None
    }

    /// Immediately free a slot that was just allocated but not yet queued.
    #[allow(dead_code)]
    pub fn free(&self, handle: OpHandle) {
        let slot = &self.slots[handle.idx];
        slot.state.store(STATE_FREE, Ordering::Release);
    }

    /// Poll a handle. Returns `Pending` while the worker is still running.
    /// On `Ready`, the slot is freed automatically.
    pub fn poll(&self, handle: OpHandle, cx: &mut Context<'_>) -> Poll<OpOutput> {
        let slot = &self.slots[handle.idx];
        let state = slot.state.load(Ordering::Acquire);
        match state {
            STATE_COMPLETE => {
                let result = unsafe { (*slot.result.get()).assume_init_read() };
                slot.state.store(STATE_FREE, Ordering::Release);
                Poll::Ready(result)
            }
            STATE_CANCELLED => {
                slot.state.store(STATE_FREE, Ordering::Release);
                Poll::Ready(OpOutput::Unit(Err(CryptoError::HardwareError)))
            }
            _ => {
                slot.waker.register(cx.waker());
                // Double-check after registering to avoid lost wakeups.
                let state = slot.state.load(Ordering::Acquire);
                if state == STATE_COMPLETE {
                    let result = unsafe { (*slot.result.get()).assume_init_read() };
                    slot.state.store(STATE_FREE, Ordering::Release);
                    Poll::Ready(result)
                } else if state == STATE_CANCELLED {
                    slot.state.store(STATE_FREE, Ordering::Release);
                    Poll::Ready(OpOutput::Unit(Err(CryptoError::HardwareError)))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    /// Cancel an in-flight operation. Effective if PENDING or RUNNING.
    pub fn cancel(&self, handle: OpHandle) {
        let slot = &self.slots[handle.idx];
        let state = slot.state.load(Ordering::Acquire);
        if state == STATE_PENDING {
            let _ = slot.state.compare_exchange(
                STATE_PENDING,
                STATE_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            slot.waker.wake();
        } else if state == STATE_RUNNING {
            let _ = slot.state.compare_exchange(
                STATE_RUNNING,
                STATE_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            slot.waker.wake();
        }
        // If COMPLETE or already FREE: nothing to do.
    }

    /// Called by a worker to claim a `PENDING` slot.
    /// Returns `false` if the slot was cancelled before we got to it.
    pub fn claim_for_run(&self, handle: OpHandle) -> bool {
        let slot = &self.slots[handle.idx];
        slot.state
            .compare_exchange(
                STATE_PENDING,
                STATE_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Called by a worker after executing the operation.
    pub fn complete(&self, handle: OpHandle, result: OpOutput) {
        let slot = &self.slots[handle.idx];
        let state = slot.state.load(Ordering::Acquire);
        if state == STATE_RUNNING {
            unsafe {
                (*slot.result.get()).write(result);
            }
            slot.state.store(STATE_COMPLETE, Ordering::Release);
            slot.waker.wake();
        } else if state == STATE_CANCELLED {
            // Operation was cancelled while running; just free the slot.
            slot.state.store(STATE_FREE, Ordering::Release);
            slot.waker.wake();
        }
        // Any other state is a logic bug.
    }

    /// Return the `OpKind` stored in a claimed slot.
    ///
    /// # Safety
    /// Caller must have successfully claimed the slot via `claim_for_run`.
    pub unsafe fn kind(&self, handle: OpHandle) -> &OpKind {
        let slot = &self.slots[handle.idx];
        unsafe { &*(*slot.kind.get()).as_mut_ptr() }
    }

    /// Check if a slot is in the PENDING state.
    pub fn is_pending(&self, handle: OpHandle) -> bool {
        self.slots[handle.idx].state.load(Ordering::Acquire) == STATE_PENDING
    }

    /// Check if a slot has been cancelled.
    pub fn is_cancelled(&self, handle: OpHandle) -> bool {
        self.slots[handle.idx].state.load(Ordering::Acquire) == STATE_CANCELLED
    }

    /// Register a waker to be notified on state change.
    pub fn register_waker(&self, handle: OpHandle, waker: &core::task::Waker) {
        self.slots[handle.idx].waker.register(waker);
    }
}

/// One slot in the fixed-size hash context table.
pub struct ContextSlot {
    state: AtomicU8,
    driver_idx: UnsafeCell<MaybeUninit<usize>>,
    ctx: UnsafeCell<MaybeUninit<Sha256Context>>,
}

// SAFETY: ContextSlot is only accessed through ContextTable's atomic state machine.
unsafe impl Send for ContextSlot {}
unsafe impl Sync for ContextSlot {}

impl Default for ContextSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(CTX_STATE_FREE),
            driver_idx: UnsafeCell::new(MaybeUninit::uninit()),
            ctx: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

/// Fixed-size pool of SHA-256 streaming contexts.
///
/// Contexts are allocated by `sha256_init`, used by `sha256_update` /
/// `sha256_finalize`, and freed by `sha256_finalize` (or on init failure).
pub struct ContextTable<const N: usize> {
    slots: [ContextSlot; N],
}

impl<const N: usize> Default for ContextTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ContextTable<N> {
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| ContextSlot::new()),
        }
    }

    /// Try to allocate a free context slot.
    /// Transitions FREE → INIT on success.
    pub fn alloc(&self) -> Option<ContextHandle> {
        for (i, slot) in self.slots.iter().enumerate() {
            if slot
                .state
                .compare_exchange(
                    CTX_STATE_FREE,
                    CTX_STATE_INIT,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return Some(ContextHandle { idx: i });
            }
        }
        None
    }

    /// Free a context slot, transitioning any state → FREE.
    pub fn free(&self, handle: ContextHandle) {
        self.slots[handle.idx]
            .state
            .store(CTX_STATE_FREE, Ordering::Release);
    }

    /// Transition INIT → BUSY.
    /// Returns false if the slot was not in INIT state.
    pub fn set_busy(&self, handle: ContextHandle) -> bool {
        self.slots[handle.idx]
            .state
            .compare_exchange(
                CTX_STATE_INIT,
                CTX_STATE_BUSY,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Transition BUSY → INIT.
    pub fn return_to_init(&self, handle: ContextHandle) {
        self.slots[handle.idx]
            .state
            .store(CTX_STATE_INIT, Ordering::Release);
    }

    /// Store the driver index that owns this context.
    ///
    /// # Safety
    /// Caller must have allocated the slot and not yet freed it.
    pub unsafe fn set_driver_idx(&self, handle: ContextHandle, idx: usize) {
        let slot = &self.slots[handle.idx];
        (*slot.driver_idx.get()).write(idx);
    }

    /// Get the driver index that owns this context.
    ///
    /// # Safety
    /// Caller must ensure the slot is in INIT or BUSY state.
    pub unsafe fn driver_idx(&self, handle: ContextHandle) -> usize {
        let slot = &self.slots[handle.idx];
        *(*slot.driver_idx.get()).as_mut_ptr()
    }

    /// Get a mutable reference to the context data.
    ///
    /// # Safety
    /// Caller must ensure the slot is in INIT or BUSY state and that no
    /// other reference to this context exists concurrently.
    pub unsafe fn ctx_mut(&self, handle: ContextHandle) -> &mut Sha256Context {
        let slot = &self.slots[handle.idx];
        &mut *(*slot.ctx.get()).as_mut_ptr()
    }
}
