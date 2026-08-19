use core::future::Future;
use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::waitqueue::AtomicWaker;

use embassy_crypto_driver::{BlockingCryptoDriver, Capabilities, CryptoDriver, CryptoError};

use crate::queue::{OpHandle, OpTable};

/// Maximum number of drivers supported by CryptoRunner.
pub const MAX_DRIVERS: usize = 5;

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
/// `Drivers` is a tuple of `&Mutex<CriticalSectionRawMutex, D>` references.
/// `T` is the maximum number of in-flight ops.
pub struct CryptoRunner<Drivers, const T: usize> {
    drivers: Drivers,
    driver_slots: [DriverSlot; MAX_DRIVERS],
    num_drivers: usize,
    op_table: OpTable<T>,
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
                let caps_match = {
                    let kind = unsafe { op_table.kind(handle) };
                    driver_caps.contains(kind.required_caps())
                };
                if caps_match {
                    if op_table.claim_for_run(handle) {
                        let mut guard = driver.lock().await;
                        let result = unsafe { op_table.kind(handle).execute(&mut *guard).await };
                        op_table.complete(handle, result);
                        found = true;
                        break;
                    }
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
    for i in 0..num_drivers {
        if slots[i].caps.contains(caps) {
            slots[i].waker.wake();
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
}

/// Object-safe backend used by `CryptoServer`.
pub(crate) trait RunnerBackend {
    fn try_blocking(
        &self,
        required: Capabilities,
        f: &mut dyn FnMut(&mut dyn BlockingCryptoDriver) -> Result<(), CryptoError>,
    ) -> Option<Result<(), CryptoError>>;

    fn schedule_aes_gcm_128_encrypt(
        &self,
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        plaintext: *const [u8],
        ciphertext: *mut [u8],
        tag: *mut [u8; 16],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_aes_gcm_128_decrypt(
        &self,
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        ciphertext: *const [u8],
        plaintext: *mut [u8],
        tag: *const [u8; 16],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_aes_gcm_256_encrypt(
        &self,
        key: *const [u8; 32],
        nonce: *const [u8],
        aad: *const [u8],
        plaintext: *const [u8],
        ciphertext: *mut [u8],
        tag: *mut [u8; 16],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_aes_gcm_256_decrypt(
        &self,
        key: *const [u8; 32],
        nonce: *const [u8],
        aad: *const [u8],
        ciphertext: *const [u8],
        plaintext: *mut [u8],
        tag: *const [u8; 16],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_sha_256(
        &self,
        data: *const [u8],
        out: *mut [u8; 32],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_sha_384(
        &self,
        data: *const [u8],
        out: *mut [u8; 48],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_p256_keygen(
        &self,
        secret_key: *mut [u8; 32],
        public_key: *mut [u8; 64],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_p256_ecdh(
        &self,
        secret_key: *const [u8; 32],
        public_key: *const [u8; 64],
        shared_secret: *mut [u8; 32],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_p256_ecdsa_sign(
        &self,
        secret_key: *const [u8; 32],
        digest: *const [u8; 32],
        signature: *mut [u8; 64],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_p256_ecdsa_verify(
        &self,
        public_key: *const [u8; 64],
        digest: *const [u8; 32],
        signature: *const [u8; 64],
    ) -> Result<OpHandle, CryptoError>;

    fn poll_op(&self, handle: OpHandle, cx: &mut Context<'_>) -> Poll<Result<(), CryptoError>>;
    fn cancel_op(&self, handle: OpHandle) -> Result<(), CryptoError>;
}

macro_rules! impl_crypto_runner {
      ($($idx:tt => $T:ident),+) => {
        impl<'a, $($T: CryptoDriver),+, const T: usize> CryptoRunner<
            ($(&'a Mutex<CriticalSectionRawMutex, $T>,)+),
            T,
        > {
            pub fn new(drivers: ($(&'a Mutex<CriticalSectionRawMutex, $T>,)+)) -> Self {
                let driver_slots = [const { DriverSlot::new(Capabilities(0)) }; MAX_DRIVERS];
                let num_drivers = {
                    let mut n = 0usize;
                    $({ n += 1; let _ = $idx; })+
                    n
                };
                Self {
                    drivers,
                    driver_slots,
                    num_drivers,
                    op_table: OpTable::new(),
                }
            }

            /// Run all driver workers concurrently.
            ///
            /// This method never returns.
            #[allow(unreachable_code)]
            pub async fn run(&self) -> ! {
                join_n!(
                    $(driver_worker(self.drivers.$idx, &self.driver_slots[$idx], &self.op_table)),+
                ).await;

                unreachable!();
            }

            /// Obtain a type-erased server handle.
            pub fn server(&self) -> crate::server::CryptoServer<'_> {
                crate::server::CryptoServer { backend: self }
            }
        }

        impl<'a, $($T: CryptoDriver),+, const T: usize> RunnerBackend
            for CryptoRunner<($(&'a Mutex<CriticalSectionRawMutex, $T>,)+), T>
        {
            fn try_blocking(
                &self,
                required: Capabilities,
                f: &mut dyn FnMut(&mut dyn BlockingCryptoDriver) -> Result<(), CryptoError>,
            ) -> Option<Result<(), CryptoError>> {
                $({
                    if let Ok(mut guard) = self.drivers.$idx.try_lock() {
                        if guard.capabilities().contains(required) {
                            return Some(f(&mut *guard));
                        }
                    }
                })+
                None
            }

            fn schedule_aes_gcm_128_encrypt(
                &self,
                key: *const [u8; 16],
                nonce: *const [u8],
                aad: *const [u8],
                plaintext: *const [u8],
                ciphertext: *mut [u8],
                tag: *mut [u8; 16],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::AesGcm128Encrypt { key, nonce, aad, plaintext, ciphertext, tag };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::AES_128_GCM, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_aes_gcm_128_decrypt(
                &self,
                key: *const [u8; 16],
                nonce: *const [u8],
                aad: *const [u8],
                ciphertext: *const [u8],
                plaintext: *mut [u8],
                tag: *const [u8; 16],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::AesGcm128Decrypt { key, nonce, aad, ciphertext, plaintext, tag };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::AES_128_GCM, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_aes_gcm_256_encrypt(
                &self,
                key: *const [u8; 32],
                nonce: *const [u8],
                aad: *const [u8],
                plaintext: *const [u8],
                ciphertext: *mut [u8],
                tag: *mut [u8; 16],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::AesGcm256Encrypt { key, nonce, aad, plaintext, ciphertext, tag };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::AES_256_GCM, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_aes_gcm_256_decrypt(
                &self,
                key: *const [u8; 32],
                nonce: *const [u8],
                aad: *const [u8],
                ciphertext: *const [u8],
                plaintext: *mut [u8],
                tag: *const [u8; 16],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::AesGcm256Decrypt { key, nonce, aad, ciphertext, plaintext, tag };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::AES_256_GCM, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_sha_256(
                &self,
                data: *const [u8],
                out: *mut [u8; 32],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::Sha256 { data, out };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::SHA_256, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_sha_384(
                &self,
                data: *const [u8],
                out: *mut [u8; 48],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::Sha384 { data, out };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::SHA_384, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_p256_keygen(
                &self,
                secret_key: *mut [u8; 32],
                public_key: *mut [u8; 64],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::P256Keygen { secret_key, public_key };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::P256_KEYGEN, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_p256_ecdh(
                &self,
                secret_key: *const [u8; 32],
                public_key: *const [u8; 64],
                shared_secret: *mut [u8; 32],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::P256Ecdh { secret_key, public_key, shared_secret };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::P256_ECDH, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_p256_ecdsa_sign(
                &self,
                secret_key: *const [u8; 32],
                digest: *const [u8; 32],
                signature: *mut [u8; 64],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::P256EcdsaSign { secret_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::P256_ECDSA_SIGN, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_p256_ecdsa_verify(
                &self,
                public_key: *const [u8; 64],
                digest: *const [u8; 32],
                signature: *const [u8; 64],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::P256EcdsaVerify { public_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::P256_ECDSA_VERIFY, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn poll_op(&self, handle: OpHandle, cx: &mut Context<'_>) -> Poll<Result<(), CryptoError>> {
                self.op_table.poll(handle, cx)
            }

            fn cancel_op(&self, handle: OpHandle) -> Result<(), CryptoError> {
                self.op_table.cancel(handle);
                Ok(())
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
