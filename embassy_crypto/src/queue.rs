use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::{Context, Poll};
use embassy_sync::waitqueue::AtomicWaker;

use embassy_crypto_driver::{Capabilities, CryptoDriver, CryptoError};

const STATE_FREE: u8 = 0;
const STATE_PENDING: u8 = 1;
const STATE_RUNNING: u8 = 2;
const STATE_COMPLETE: u8 = 3;
const STATE_CANCELLED: u8 = 4;

/// Opaque handle to an in-flight operation in the `OpTable`.
#[derive(Clone, Copy)]
pub struct OpHandle {
    pub(crate) idx: usize,
}

/// Discriminated union of all async operations the runner can schedule.
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
}

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
            Self::Sha256 { .. } => Capabilities::SHA_256,
            Self::Sha384 { .. } => Capabilities::SHA_384,
            Self::P256Keygen { .. } => Capabilities::P256_KEYGEN,
            Self::P256Ecdh { .. } => Capabilities::P256_ECDH,
            Self::P256EcdsaSign { .. } => Capabilities::P256_ECDSA_SIGN,
            Self::P256EcdsaVerify { .. } => Capabilities::P256_ECDSA_VERIFY,
        }
    }

    /// Execute this operation on the given driver.
    ///
    /// # Safety
    /// All raw pointers stored in this `OpKind` must be valid and unaliased
    /// for the duration of the async call.
    pub async unsafe fn execute<D: CryptoDriver>(&self, driver: &mut D) -> Result<(), CryptoError> {
        match self {
            Self::AesGcm128Encrypt {
                key,
                nonce,
                aad,
                plaintext,
                ciphertext,
                tag,
            } => {
                driver
                    .aes_gcm_128_encrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**plaintext },
                        unsafe { &mut **ciphertext },
                        unsafe { &mut **tag },
                    )
                    .await
            }
            Self::AesGcm128Decrypt {
                key,
                nonce,
                aad,
                ciphertext,
                plaintext,
                tag,
            } => {
                driver
                    .aes_gcm_128_decrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**ciphertext },
                        unsafe { &mut **plaintext },
                        unsafe { &**tag },
                    )
                    .await
            }
            Self::AesGcm256Encrypt {
                key,
                nonce,
                aad,
                plaintext,
                ciphertext,
                tag,
            } => {
                driver
                    .aes_gcm_256_encrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**plaintext },
                        unsafe { &mut **ciphertext },
                        unsafe { &mut **tag },
                    )
                    .await
            }
            Self::AesGcm256Decrypt {
                key,
                nonce,
                aad,
                ciphertext,
                plaintext,
                tag,
            } => {
                driver
                    .aes_gcm_256_decrypt(
                        unsafe { &**key },
                        unsafe { &**nonce },
                        unsafe { &**aad },
                        unsafe { &**ciphertext },
                        unsafe { &mut **plaintext },
                        unsafe { &**tag },
                    )
                    .await
            }
            Self::Sha256 { data, out } => {
                driver
                    .sha_256(unsafe { &**data }, unsafe { &mut **out })
                    .await
            }
            Self::Sha384 { data, out } => {
                driver
                    .sha_384(unsafe { &**data }, unsafe { &mut **out })
                    .await
            }
            Self::P256Keygen {
                secret_key,
                public_key,
            } => {
                driver
                    .p256_keygen(unsafe { &mut **secret_key }, unsafe { &mut **public_key })
                    .await
            }
            Self::P256Ecdh {
                secret_key,
                public_key,
                shared_secret,
            } => {
                driver
                    .p256_ecdh(unsafe { &**secret_key }, unsafe { &**public_key }, unsafe {
                        &mut **shared_secret
                    })
                    .await
            }
            Self::P256EcdsaSign {
                secret_key,
                digest,
                signature,
            } => {
                driver
                    .p256_ecdsa_sign(unsafe { &**secret_key }, unsafe { &**digest }, unsafe {
                        &mut **signature
                    })
                    .await
            }
            Self::P256EcdsaVerify {
                public_key,
                digest,
                signature,
            } => {
                driver
                    .p256_ecdsa_verify(unsafe { &**public_key }, unsafe { &**digest }, unsafe {
                        &**signature
                    })
                    .await
            }
        }
    }
}

/// One slot in the fixed-size operation table.
pub struct OpSlot {
    state: AtomicU8,
    kind: UnsafeCell<MaybeUninit<OpKind>>,
    result: UnsafeCell<MaybeUninit<Result<(), CryptoError>>>,
    waker: AtomicWaker,
}

// SAFETY: OpSlot is only accessed through OpTable's atomic state machine.
unsafe impl Send for OpSlot {}
unsafe impl Sync for OpSlot {}

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
/// The worker transitions the slot through `RUNNING` → `COMPLETE`.
/// If the server future is dropped early, it may transition `PENDING` → `CANCELLED`.
pub struct OpTable<const N: usize> {
    slots: [OpSlot; N],
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
    pub fn free(&self, handle: OpHandle) {
        let slot = &self.slots[handle.idx];
        slot.state.store(STATE_FREE, Ordering::Release);
    }

    /// Poll a handle. Returns `Pending` while the worker is still running.
    /// On `Ready`, the slot is freed automatically.
    pub fn poll(&self, handle: OpHandle, cx: &mut Context<'_>) -> Poll<Result<(), CryptoError>> {
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
                Poll::Ready(Err(CryptoError::HardwareError))
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
                    Poll::Ready(Err(CryptoError::HardwareError))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    /// Cancel an in-flight operation. Only effective if still `PENDING`.
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
        }
        // If RUNNING or COMPLETE, too late to cancel.
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
    pub fn complete(&self, handle: OpHandle, result: Result<(), CryptoError>) {
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
}
