use core::future::Future;
use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll};

use core::cell::UnsafeCell;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::pipe::Pipe;
use embassy_sync::waitqueue::AtomicWaker;

use embassy_crypto_driver::{
    Algorithm, BlockingCryptoDriver, Capabilities, CryptoDriver, CryptoError,
};

use crate::queue::{ContextHandle, ContextTable, OpHandle, OpOutput, OpTable};

/// Maximum number of drivers supported by CryptoRunner.
pub const MAX_DRIVERS: usize = 5;

/// Maximum number of concurrent streaming hash contexts.
pub const MAX_CONTEXTS: usize = 4;

/// A future that yields once without self-waking.
///
/// On first poll, returns `Pending`. The task will only be re-polled when
/// an external waker (e.g., from `DriverSlot`) calls `wake()`.
/// On second poll, returns `Ready`.
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            // Intentionally does NOT call cx.waker().wake_by_ref().
            // The caller must rely on an external waker to re-poll.
            Poll::Pending
        }
    }
}

/// Yield the current task without self-waking.
///
/// The task will sleep until an external waker fires.
pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

/// One slot per driver for targeted wakeups.
pub struct DriverSlot {
    waker: AtomicWaker,
    caps: Capabilities,
}

impl DriverSlot {
    pub const fn new(caps: Capabilities) -> Self {
        Self {
            waker: AtomicWaker::new(),
            caps,
        }
    }
}

/// Hardware crypto multiplexer.
///
/// `Drivers` is a tuple of `Mutex<CriticalSectionRawMutex, D>` instances.
/// `T` is the maximum number of in-flight ops.
pub struct CryptoRunner<Drivers, const T: usize> {
    drivers: Drivers,
    driver_slots: [DriverSlot; MAX_DRIVERS],
    num_drivers: usize,
    /// Pre-computed capabilities for each driver slot (index 0..num_drivers-1).
    ///
    /// Populated at construction time so the blocking fast-path can skip
    /// `try_lock()` on drivers that do not advertise the required capability.
    driver_caps: [Capabilities; MAX_DRIVERS],
    op_table: OpTable<T>,
    context_table: ContextTable<MAX_CONTEXTS>,
    rng_pipe: UnsafeCell<Pipe<CriticalSectionRawMutex, 256>>,
}

/// Per-driver worker future. Scans the OpTable for PENDING ops it can handle.
async fn driver_worker<D: CryptoDriver, const T: usize>(
    driver: &Mutex<CriticalSectionRawMutex, D>,
    slot: &DriverSlot,
    op_table: &OpTable<T>,
) -> ! {
    let driver_caps = driver.lock().await.capabilities();

    // Publish capabilities so the scheduler knows which drivers to wake.
    // SAFETY: this is the only writer; the macro guarantees one worker per slot.
    unsafe {
        let slot_ptr = slot as *const DriverSlot as *mut DriverSlot;
        (*slot_ptr).caps = driver_caps;
    }

    loop {
        // 1. Register waker BEFORE scanning (anti-torn-read)
        poll_fn(|cx| {
            slot.waker.register(cx.waker());
            Poll::Ready(())
        })
        .await;

        // 2. Scan OpTable for PENDING ops this driver can handle
        let mut found = false;
        for i in 0..T {
            let handle = OpHandle { idx: i };
            if op_table.is_pending(handle) {
                let kind = unsafe { op_table.kind(handle) };

                if !driver_caps.contains(kind.required_caps()) {
                    continue;
                }

                if op_table.claim_for_run(handle) {
                    let mut guard = driver.lock().await;
                    let kind = unsafe { op_table.kind(handle) };

                    // Pin the execute future on the stack.
                    let exec_fut = unsafe { kind.execute(&mut *guard) };
                    let mut exec_fut = core::pin::pin!(exec_fut);

                    // Manual polling loop: check cancellation before every
                    // poll and before completing.
                    let result = core::future::poll_fn(|cx| {
                        loop {
                            // 1. Check cancellation before polling.
                            if op_table.is_cancelled(handle) {
                                return Poll::Ready(kind.cancelled_output());
                            }

                            // 2. Poll the driver future.
                            match exec_fut.as_mut().poll(cx) {
                                Poll::Pending => {
                                    // Register our waker so cancel_op can wake us.
                                    op_table.register_waker(handle, cx.waker());

                                    // Anti-torn-read: re-check cancellation
                                    // after registering the waker.
                                    if op_table.is_cancelled(handle) {
                                        continue;
                                    }
                                    return Poll::Pending;
                                }
                                Poll::Ready(result) => {
                                    // 3. Operation completed in hardware.
                                    // On multi-core the caller may have set
                                    // CANCELLED while we were inside poll().
                                    // Discard the result if so.
                                    if op_table.is_cancelled(handle) {
                                        return Poll::Ready(kind.cancelled_output());
                                    }
                                    return Poll::Ready(result);
                                }
                            }
                        }
                    })
                    .await;

                    op_table.complete(handle, result);
                    found = true;
                    break;
                }
            }
        }

        if found {
            continue;
        }

        // 3. Nothing claimable — sleep until externally woken
        yield_now().await;
    }
}

/// Broadcast-wake all drivers capable of handling the given operation.
fn wake_capable(caps: Capabilities, slots: &[DriverSlot], num_drivers: usize) {
    for slot in slots.iter().take(num_drivers) {
        if slot.caps.contains(caps) {
            slot.waker.wake();
        }
    }
}

/// Select the appropriate `embassy_futures::join::*` function based on the
/// number of futures provided.
macro_rules! join_n {
    ($f1:expr) => {
        $f1
    };
    ($f1:expr, $f2:expr) => {
        embassy_futures::join::join($f1, $f2)
    };
    ($f1:expr, $f2:expr, $f3:expr) => {
        embassy_futures::join::join3($f1, $f2, $f3)
    };
    ($f1:expr, $f2:expr, $f3:expr, $f4:expr) => {
        embassy_futures::join::join4($f1, $f2, $f3, $f4)
    };
    ($f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr) => {
        embassy_futures::join::join5($f1, $f2, $f3, $f4, $f5)
    };
    ($f1:expr, $f2:expr, $f3:expr, $f4:expr, $f5:expr, $f6:expr) => {
        embassy_futures::join::join(
            embassy_futures::join::join3($f1, $f2, $f3),
            embassy_futures::join::join3($f4, $f5, $f6),
        )
    };
}

// Object-safe backend used by `CryptoServer`.
// ------------------------------------------------------------------
// Enum dispatch for blocking operations (eliminates dyn FnMut + dyn Driver)
// ------------------------------------------------------------------

/// Discriminated union of all blocking unit-returning crypto operations.
pub(crate) enum BlockingOp<'a> {
    Aes128EcbEncrypt {
        block: &'a mut [u8; 16],
        key: &'a [u8; 16],
    },
    Aes128EcbDecrypt {
        block: &'a mut [u8; 16],
        key: &'a [u8; 16],
    },
    Aes128Cmac {
        key: &'a [u8; 16],
        data: &'a [u8],
        out: &'a mut [u8; 16],
    },
    AesCcm128Encrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    },
    AesCcm128Decrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    },
    AesCcm8_128Encrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 8],
    },
    AesCcm8_128Decrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 8],
    },
    AesGcm128Encrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    },
    AesGcm128Decrypt {
        key: &'a [u8; 16],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    },
    AesGcm256Encrypt {
        key: &'a [u8; 32],
        nonce: &'a [u8],
        aad: &'a [u8],
        plaintext: &'a [u8],
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; 16],
    },
    AesGcm256Decrypt {
        key: &'a [u8; 32],
        nonce: &'a [u8],
        aad: &'a [u8],
        ciphertext: &'a [u8],
        plaintext: &'a mut [u8],
        tag: &'a [u8; 16],
    },
    P256Keygen {
        secret_key: &'a mut [u8; 32],
        public_key: &'a mut [u8; 64],
    },
    P256Ecdh {
        secret_key: &'a [u8; 32],
        public_key: &'a [u8; 64],
        shared_secret: &'a mut [u8; 32],
    },
    P256EcdsaSign {
        secret_key: &'a [u8; 32],
        digest: &'a [u8; 32],
        signature: &'a mut [u8; 64],
    },
    P256EcdsaVerify {
        public_key: &'a [u8; 64],
        digest: &'a [u8; 32],
        signature: &'a [u8; 64],
    },
    P384Keygen {
        secret_key: &'a mut [u8; 48],
        public_key: &'a mut [u8; 96],
    },
    P384Ecdh {
        secret_key: &'a [u8; 48],
        public_key: &'a [u8; 96],
        shared_secret: &'a mut [u8; 48],
    },
    P384EcdsaSign {
        secret_key: &'a [u8; 48],
        digest: &'a [u8; 48],
        signature: &'a mut [u8; 96],
    },
    P384EcdsaVerify {
        public_key: &'a [u8; 96],
        digest: &'a [u8; 48],
        signature: &'a [u8; 96],
    },
    RsaVerifyPkcs1v15Sha256 {
        public_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a [u8],
    },
    RsaVerifyPkcs1v15Sha384 {
        public_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a [u8],
    },
    RsaVerifyPkcs1v15Sha512 {
        public_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a [u8],
    },
    RsaVerifyPssSha256 {
        public_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a [u8],
    },
    RsaVerifyPssSha384 {
        public_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a [u8],
    },
    RsaVerifyPssSha512 {
        public_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a [u8],
    },
    RngFill {
        dest: &'a mut [u8],
    },
}

impl BlockingOp<'_> {
    pub fn required_caps(&self) -> Capabilities {
        match self {
            Self::Aes128EcbEncrypt { .. } | Self::Aes128EcbDecrypt { .. } => {
                Capabilities::AES_128_ECB
            }
            Self::Aes128Cmac { .. } => Capabilities::AES_128_CMAC,
            Self::AesCcm128Encrypt { .. } | Self::AesCcm128Decrypt { .. } => {
                Capabilities::AES_128_CCM
            }
            Self::AesCcm8_128Encrypt { .. } | Self::AesCcm8_128Decrypt { .. } => {
                Capabilities::AES_128_CCM8
            }
            Self::AesGcm128Encrypt { .. } | Self::AesGcm128Decrypt { .. } => {
                Capabilities::AES_128_GCM
            }
            Self::AesGcm256Encrypt { .. } | Self::AesGcm256Decrypt { .. } => {
                Capabilities::AES_256_GCM
            }
            Self::P256Keygen { .. } => Capabilities::P256_KEYGEN,
            Self::P256Ecdh { .. } => Capabilities::P256_ECDH,
            Self::P256EcdsaSign { .. } => Capabilities::P256_ECDSA_SIGN,
            Self::P256EcdsaVerify { .. } => Capabilities::P256_ECDSA_VERIFY,
            Self::P384Keygen { .. } => Capabilities::P384_KEYGEN,
            Self::P384Ecdh { .. } => Capabilities::P384_ECDH,
            Self::P384EcdsaSign { .. } => Capabilities::P384_ECDSA_SIGN,
            Self::P384EcdsaVerify { .. } => Capabilities::P384_ECDSA_VERIFY,
            Self::RsaVerifyPkcs1v15Sha256 { .. } => Capabilities::RSA_PKCS1V15_SHA256,
            Self::RsaVerifyPkcs1v15Sha384 { .. } => Capabilities::RSA_PKCS1V15_SHA384,
            Self::RsaVerifyPkcs1v15Sha512 { .. } => Capabilities::RSA_PKCS1V15_SHA512,
            Self::RsaVerifyPssSha256 { .. } => Capabilities::RSA_PSS_SHA256,
            Self::RsaVerifyPssSha384 { .. } => Capabilities::RSA_PSS_SHA384,
            Self::RsaVerifyPssSha512 { .. } => Capabilities::RSA_PSS_SHA512,
            Self::RngFill { .. } => Capabilities::RNG,
        }
    }
}

/// Discriminated union of all blocking size-returning crypto operations.
pub(crate) enum BlockingOpSize<'a> {
    RsaSignPkcs1v15Sha256 {
        private_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a mut [u8],
    },
    RsaSignPkcs1v15Sha384 {
        private_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a mut [u8],
    },
    RsaSignPkcs1v15Sha512 {
        private_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a mut [u8],
    },
    RsaSignPssSha256 {
        private_key: &'a [u8],
        digest: &'a [u8; 32],
        signature: &'a mut [u8],
    },
    RsaSignPssSha384 {
        private_key: &'a [u8],
        digest: &'a [u8; 48],
        signature: &'a mut [u8],
    },
    RsaSignPssSha512 {
        private_key: &'a [u8],
        digest: &'a [u8; 64],
        signature: &'a mut [u8],
    },
}

impl BlockingOpSize<'_> {
    pub fn required_caps(&self) -> Capabilities {
        match self {
            Self::RsaSignPkcs1v15Sha256 { .. } => Capabilities::RSA_PKCS1V15_SHA256,
            Self::RsaSignPkcs1v15Sha384 { .. } => Capabilities::RSA_PKCS1V15_SHA384,
            Self::RsaSignPkcs1v15Sha512 { .. } => Capabilities::RSA_PKCS1V15_SHA512,
            Self::RsaSignPssSha256 { .. } => Capabilities::RSA_PSS_SHA256,
            Self::RsaSignPssSha384 { .. } => Capabilities::RSA_PSS_SHA384,
            Self::RsaSignPssSha512 { .. } => Capabilities::RSA_PSS_SHA512,
        }
    }
}

/// Maps enum variants to concrete `BlockingCryptoDriver` method calls.
///
/// Blanket impl keeps `impl_crypto_runner!` macro clean — no per-variant codegen.
pub(crate) trait BlockingDispatcher {
    fn dispatch(&mut self, op: BlockingOp<'_>) -> Result<(), CryptoError>;
    fn dispatch_size(&mut self, op: BlockingOpSize<'_>) -> Result<usize, CryptoError>;
}

impl<T: BlockingCryptoDriver> BlockingDispatcher for T {
    fn dispatch(&mut self, op: BlockingOp<'_>) -> Result<(), CryptoError> {
        match op {
            BlockingOp::Aes128EcbEncrypt { block, key } => {
                self.blocking_aes_128_ecb_encrypt(block, key)
            }
            BlockingOp::Aes128EcbDecrypt { block, key } => {
                self.blocking_aes_128_ecb_decrypt(block, key)
            }
            BlockingOp::Aes128Cmac { key, data, out } => self.blocking_aes_128_cmac(key, data, out),
            BlockingOp::AesCcm128Encrypt {
                key,
                nonce,
                aad,
                plaintext,
                ciphertext,
                tag,
            } => self.blocking_aes_ccm_128_encrypt(key, nonce, aad, plaintext, ciphertext, tag),
            BlockingOp::AesCcm128Decrypt {
                key,
                nonce,
                aad,
                ciphertext,
                plaintext,
                tag,
            } => self.blocking_aes_ccm_128_decrypt(key, nonce, aad, ciphertext, plaintext, tag),
            BlockingOp::AesCcm8_128Encrypt {
                key,
                nonce,
                aad,
                plaintext,
                ciphertext,
                tag,
            } => self.blocking_aes_ccm8_128_encrypt(key, nonce, aad, plaintext, ciphertext, tag),
            BlockingOp::AesCcm8_128Decrypt {
                key,
                nonce,
                aad,
                ciphertext,
                plaintext,
                tag,
            } => self.blocking_aes_ccm8_128_decrypt(key, nonce, aad, ciphertext, plaintext, tag),
            BlockingOp::AesGcm128Encrypt {
                key,
                nonce,
                aad,
                plaintext,
                ciphertext,
                tag,
            } => self.blocking_aes_gcm_128_encrypt(key, nonce, aad, plaintext, ciphertext, tag),
            BlockingOp::AesGcm128Decrypt {
                key,
                nonce,
                aad,
                ciphertext,
                plaintext,
                tag,
            } => self.blocking_aes_gcm_128_decrypt(key, nonce, aad, ciphertext, plaintext, tag),
            BlockingOp::AesGcm256Encrypt {
                key,
                nonce,
                aad,
                plaintext,
                ciphertext,
                tag,
            } => self.blocking_aes_gcm_256_encrypt(key, nonce, aad, plaintext, ciphertext, tag),
            BlockingOp::AesGcm256Decrypt {
                key,
                nonce,
                aad,
                ciphertext,
                plaintext,
                tag,
            } => self.blocking_aes_gcm_256_decrypt(key, nonce, aad, ciphertext, plaintext, tag),
            BlockingOp::P256Keygen {
                secret_key,
                public_key,
            } => self.blocking_p256_keygen(secret_key, public_key),
            BlockingOp::P256Ecdh {
                secret_key,
                public_key,
                shared_secret,
            } => self.blocking_p256_ecdh(secret_key, public_key, shared_secret),
            BlockingOp::P256EcdsaSign {
                secret_key,
                digest,
                signature,
            } => self.blocking_p256_ecdsa_sign(secret_key, digest, signature),
            BlockingOp::P256EcdsaVerify {
                public_key,
                digest,
                signature,
            } => self.blocking_p256_ecdsa_verify(public_key, digest, signature),
            BlockingOp::P384Keygen {
                secret_key,
                public_key,
            } => self.blocking_p384_keygen(secret_key, public_key),
            BlockingOp::P384Ecdh {
                secret_key,
                public_key,
                shared_secret,
            } => self.blocking_p384_ecdh(secret_key, public_key, shared_secret),
            BlockingOp::P384EcdsaSign {
                secret_key,
                digest,
                signature,
            } => self.blocking_p384_ecdsa_sign(secret_key, digest, signature),
            BlockingOp::P384EcdsaVerify {
                public_key,
                digest,
                signature,
            } => self.blocking_p384_ecdsa_verify(public_key, digest, signature),
            BlockingOp::RsaVerifyPkcs1v15Sha256 {
                public_key,
                digest,
                signature,
            } => self.blocking_rsa_verify_pkcs1v15_sha256(public_key, digest, signature),
            BlockingOp::RsaVerifyPkcs1v15Sha384 {
                public_key,
                digest,
                signature,
            } => self.blocking_rsa_verify_pkcs1v15_sha384(public_key, digest, signature),
            BlockingOp::RsaVerifyPkcs1v15Sha512 {
                public_key,
                digest,
                signature,
            } => self.blocking_rsa_verify_pkcs1v15_sha512(public_key, digest, signature),
            BlockingOp::RsaVerifyPssSha256 {
                public_key,
                digest,
                signature,
            } => self.blocking_rsa_verify_pss_sha256(public_key, digest, signature),
            BlockingOp::RsaVerifyPssSha384 {
                public_key,
                digest,
                signature,
            } => self.blocking_rsa_verify_pss_sha384(public_key, digest, signature),
            BlockingOp::RsaVerifyPssSha512 {
                public_key,
                digest,
                signature,
            } => self.blocking_rsa_verify_pss_sha512(public_key, digest, signature),
            BlockingOp::RngFill { dest } => self.blocking_rng_fill(dest),
        }
    }

    fn dispatch_size(&mut self, op: BlockingOpSize<'_>) -> Result<usize, CryptoError> {
        match op {
            BlockingOpSize::RsaSignPkcs1v15Sha256 {
                private_key,
                digest,
                signature,
            } => self.blocking_rsa_sign_pkcs1v15_sha256(private_key, digest, signature),
            BlockingOpSize::RsaSignPkcs1v15Sha384 {
                private_key,
                digest,
                signature,
            } => self.blocking_rsa_sign_pkcs1v15_sha384(private_key, digest, signature),
            BlockingOpSize::RsaSignPkcs1v15Sha512 {
                private_key,
                digest,
                signature,
            } => self.blocking_rsa_sign_pkcs1v15_sha512(private_key, digest, signature),
            BlockingOpSize::RsaSignPssSha256 {
                private_key,
                digest,
                signature,
            } => self.blocking_rsa_sign_pss_sha256(private_key, digest, signature),
            BlockingOpSize::RsaSignPssSha384 {
                private_key,
                digest,
                signature,
            } => self.blocking_rsa_sign_pss_sha384(private_key, digest, signature),
            BlockingOpSize::RsaSignPssSha512 {
                private_key,
                digest,
                signature,
            } => self.blocking_rsa_sign_pss_sha512(private_key, digest, signature),
        }
    }
}

/// Object-safe backend used by `CryptoServer`.
pub(crate) trait RunnerBackend {
    fn dispatch_blocking(&self, op: BlockingOp<'_>) -> Option<Result<(), CryptoError>>;
    fn dispatch_blocking_size(&self, op: BlockingOpSize<'_>) -> Option<Result<usize, CryptoError>>;

    fn try_context_init(&self, op: Algorithm) -> Result<ContextHandle, CryptoError>;
    fn try_context_update(
        &self,
        handle: ContextHandle,
        op: Algorithm,
        data: &[u8],
    ) -> Result<(), CryptoError>;
    fn try_context_finalize(
        &self,
        handle: ContextHandle,
        op: Algorithm,
        out: &mut [u8],
    ) -> Result<(), CryptoError>;

    fn schedule(&self, kind: crate::queue::OpKind) -> Result<OpHandle, CryptoError>;

    fn poll_op(&self, handle: OpHandle, cx: &mut Context<'_>) -> Poll<OpOutput>;
    fn cancel_op(&self, handle: OpHandle) -> Result<(), CryptoError>;

    fn try_rng_fill(&self, dest: &mut [u8]) -> Option<Result<(), CryptoError>>;

    fn try_hmac_init(&self, op: Algorithm, key: &[u8]) -> Result<ContextHandle, CryptoError>;
}

macro_rules! impl_crypto_runner {
      ($($idx:tt => $T:ident),+) => {
        impl<$($T: CryptoDriver),+, const T: usize> CryptoRunner<
            ($(Mutex<CriticalSectionRawMutex, $T>,)+),
            T,
        > {
            pub fn new(drivers: ($($T,)+)) -> Self {
                let driver_slots = [const { DriverSlot::new(Capabilities(0)) }; MAX_DRIVERS];
                let mut driver_caps = [Capabilities(0); MAX_DRIVERS];
                let num_drivers = {
                    let mut n = 0usize;
                    $({ n += 1; let _ = $idx; })+
                    n
                };
                $({ driver_caps[$idx] = drivers.$idx.capabilities(); })+
                Self {
                    drivers: ($(Mutex::<CriticalSectionRawMutex, _>::new(drivers.$idx),)+),
                    driver_slots,
                    num_drivers,
                    driver_caps,
                    op_table: OpTable::new(),
                    context_table: ContextTable::new(),
                    rng_pipe: UnsafeCell::new(Pipe::new()),
                }
            }

            /// Refill the RNG pipe asynchronously.
            async fn rng_refill(&self) {
                let mut temp = [0u8; 256];
                loop {
                    $({
                        if self.driver_caps[$idx].contains(Capabilities::RNG) {
                            if let Ok(mut guard) = self.drivers.$idx.try_lock() {
                                if (&mut *guard).fill_rng_async(&mut temp).await.is_ok() {
                                    let pipe = unsafe { &mut *self.rng_pipe.get() };
                                    let mut written = 0;
                                    while written < temp.len() {
                                        written += pipe.write(&temp[written..]).await;
                                    }
                                }
                            }

                            continue;
                        }
                    })+

                    break;
                }
            }

            /// Run all driver workers concurrently.
            ///
            /// This method never returns.
            #[allow(unreachable_code)]
            pub async fn run(&self) -> ! {
                join_n!(
                    self.rng_refill(),
                    $(driver_worker(&self.drivers.$idx, &self.driver_slots[$idx], &self.op_table)),+
                ).await;

                unreachable!();
            }

            /// Obtain a type-erased server handle.
            pub fn server(&self) -> crate::server::CryptoServer<'_> {
                crate::server::CryptoServer { backend: self }
            }
        }
        impl<$($T: CryptoDriver),+, const T: usize> RunnerBackend
            for CryptoRunner<($(Mutex<CriticalSectionRawMutex, $T>,)+), T>
        {
            fn dispatch_blocking(
                &self,
                op: crate::runner::BlockingOp<'_>,
            ) -> Option<Result<(), CryptoError>> {
                $({
                    if self.driver_caps[$idx].contains(op.required_caps()) {
                        if let Ok(mut guard) = self.drivers.$idx.try_lock() {
                            return Some(guard.dispatch(op));
                        }
                    }
                })+
                None
            }

            fn dispatch_blocking_size(
                &self,
                op: crate::runner::BlockingOpSize<'_>,
            ) -> Option<Result<usize, CryptoError>> {
                $({
                    if self.driver_caps[$idx].contains(op.required_caps()) {
                        if let Ok(mut guard) = self.drivers.$idx.try_lock() {
                            return Some(guard.dispatch_size(op));
                        }
                    }
                })+
                None
            }

            fn try_context_init(&self, op: Algorithm) -> Result<ContextHandle, CryptoError> {
                let handle = self.context_table.alloc()
                    .ok_or(CryptoError::HardwareError)?;
                let required = op.required_caps();

                $({
                    if self.driver_caps[$idx].contains(required) {
                        if let Ok(mut guard) = self.drivers.$idx.try_lock() {
                            let ctx = unsafe { &mut *self.context_table.ctx_mut(handle) };
                            guard.blocking_hash_init(op, ctx)?;
                            unsafe {
                                self.context_table.set_driver_idx(handle, $idx);
                            }
                            return Ok(handle);
                        }
                    }
                })+

                self.context_table.free(handle);
                Err(CryptoError::HardwareError)
            }

            fn try_hmac_init(
                &self,
                op: Algorithm,
                key: &[u8],
            ) -> Result<ContextHandle, CryptoError> {
                let handle = self.context_table.alloc()
                    .ok_or(CryptoError::HardwareError)?;
                let required = op.required_caps();

                $({
                    if self.driver_caps[$idx].contains(required) {
                        if let Ok(mut guard) = self.drivers.$idx.try_lock() {
                            let ctx = unsafe { &mut *self.context_table.ctx_mut(handle) };
                            guard.blocking_hmac_init(op, key, ctx)?;
                            unsafe {
                                self.context_table.set_driver_idx(handle, $idx);
                            }
                            return Ok(handle);
                        }
                    }
                })+

                self.context_table.free(handle);
                Err(CryptoError::HardwareError)
            }

            fn try_context_update(&self, handle: ContextHandle, op: Algorithm, data: &[u8]) -> Result<(), CryptoError> {
                let driver_idx = unsafe { self.context_table.driver_idx(handle) };
                let ctx = unsafe { &mut *self.context_table.ctx_mut(handle) };

                $({
                    if driver_idx == $idx {
                        if let Ok(mut guard) = self.drivers.$idx.try_lock() {
                            return guard.blocking_hash_update(op, ctx, data);
                        }
                    }
                })+

                Err(CryptoError::HardwareError)
            }

            fn try_context_finalize(&self, handle: ContextHandle, op: Algorithm, out: &mut [u8]) -> Result<(), CryptoError> {
                let driver_idx = unsafe { self.context_table.driver_idx(handle) };
                let ctx = unsafe { &mut *self.context_table.ctx_mut(handle) };

                $({
                    if driver_idx == $idx {
                        if let Ok(mut guard) = self.drivers.$idx.try_lock() {
                            let result = guard.blocking_hash_finalize(op, ctx, out);
                            self.context_table.free(handle);
                            return result;
                        }
                    }
                })+

                self.context_table.free(handle);
                Err(CryptoError::HardwareError)
            }

            fn schedule(&self, kind: crate::queue::OpKind) -> Result<OpHandle, CryptoError> {
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(kind.required_caps(), &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn poll_op(&self, handle: OpHandle, cx: &mut Context<'_>) -> Poll<OpOutput> {
                self.op_table.poll(handle, cx)
            }

            fn cancel_op(&self, handle: OpHandle) -> Result<(), CryptoError> {
                self.op_table.cancel(handle);
                Ok(())
            }

            fn try_rng_fill(&self, dest: &mut [u8]) -> Option<Result<(), CryptoError>> {
                let pipe = unsafe { &mut *self.rng_pipe.get() };
                if pipe.len() >= dest.len() {
                    let mut total = 0;
                    while total < dest.len() {
                        total += pipe.try_read(&mut dest[total..]).ok()?;
                    }
                    Some(Ok(()))
                } else {
                    None
                }
            }
        }
    };
}

// Generate implementations for 1 through 5 drivers.
impl_crypto_runner!(0 => T0);
impl_crypto_runner!(0 => T0, 1 => T1);
impl_crypto_runner!(0 => T0, 1 => T1, 2 => T2);
impl_crypto_runner!(0 => T0, 1 => T1, 2 => T2, 3 => T3);
impl_crypto_runner!(0 => T0, 1 => T1, 2 => T2, 3 => T3, 4 => T4);
