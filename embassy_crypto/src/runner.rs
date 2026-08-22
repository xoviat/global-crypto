use core::future::Future;
use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::waitqueue::AtomicWaker;

use embassy_crypto_driver::{BlockingCryptoDriver, Capabilities, CryptoDriver, CryptoError};

use crate::queue::{ContextHandle, ContextTable, OpHandle, OpOutput, OpTable};

/// Maximum number of drivers supported by CryptoRunner.
pub const MAX_DRIVERS: usize = 5;

/// Maximum number of concurrent SHA-256 streaming contexts.
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
/// `Drivers` is a tuple of `&Mutex<CriticalSectionRawMutex, D>` references.
/// `T` is the maximum number of in-flight ops.
pub struct CryptoRunner<Drivers, const T: usize> {
    drivers: Drivers,
    driver_slots: [DriverSlot; MAX_DRIVERS],
    num_drivers: usize,
    op_table: OpTable<T>,
    context_table: ContextTable<MAX_CONTEXTS>,
}

/// Per-driver worker future. Scans the OpTable for PENDING ops it can handle.
async fn driver_worker<D: CryptoDriver, const T: usize>(
    driver: &Mutex<CriticalSectionRawMutex, D>,
    slot: &DriverSlot,
    op_table: &OpTable<T>,
    context_table: &ContextTable<MAX_CONTEXTS>,
    driver_idx: usize,
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

                // Streaming ops must be handled by the driver that owns the context.
                if kind.is_streaming() {
                    let ctx_handle = kind.ctx_handle();
                    let bound_driver = unsafe { context_table.driver_idx(ctx_handle) };
                    if bound_driver != driver_idx {
                        continue;
                    }
                } else if !driver_caps.contains(kind.required_caps()) {
                    continue;
                }

                if op_table.claim_for_run(handle) {
                    let mut guard = driver.lock().await;
                    let kind = unsafe { op_table.kind(handle) };

                    let result = if kind.is_streaming() {
                        // Streaming ops are executed directly by the worker
                        // so the context can be borrowed across the await point.
                        execute_streaming_op(&mut *guard, kind, context_table, op_table, handle)
                            .await
                    } else {
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

                        // Explicitly drop the driver future before completing so
                        // its Drop impl can abort DMA / clean hardware state
                        // before the caller is woken and potentially frees buffers.
                        drop(exec_fut);

                        result
                    };

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

/// Execute a streaming operation directly in the worker.
///
/// This is inlined so the context can be borrowed across the await point
/// without storing it in `OpKind`.
async fn execute_streaming_op<D: CryptoDriver, const T: usize>(
    driver: &mut D,
    kind: &crate::queue::OpKind,
    context_table: &ContextTable<MAX_CONTEXTS>,
    op_table: &OpTable<T>,
    handle: OpHandle,
) -> OpOutput {
    match kind {
        crate::queue::OpKind::Sha256Update { ctx_handle, data } => {
            // Transition context to BUSY
            if !context_table.set_busy(*ctx_handle) {
                return OpOutput::Unit(Err(CryptoError::HardwareError));
            }

            let ctx = unsafe { context_table.ctx_mut(*ctx_handle) };
            let exec_fut = driver.sha256_update(ctx, unsafe { &**data });
            let mut exec_fut = core::pin::pin!(exec_fut);

            let result = core::future::poll_fn(|cx| {
                loop {
                    if op_table.is_cancelled(handle) {
                        context_table.return_to_init(*ctx_handle);
                        return Poll::Ready(Err(CryptoError::HardwareError));
                    }
                    match exec_fut.as_mut().poll(cx) {
                        Poll::Pending => {
                            op_table.register_waker(handle, cx.waker());
                            if op_table.is_cancelled(handle) {
                                continue;
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(result) => {
                            if op_table.is_cancelled(handle) {
                                context_table.return_to_init(*ctx_handle);
                                return Poll::Ready(Err(CryptoError::HardwareError));
                            }
                            return Poll::Ready(result);
                        }
                    }
                }
            })
            .await;

            drop(exec_fut);
            context_table.return_to_init(*ctx_handle);
            OpOutput::Unit(result)
        }
        crate::queue::OpKind::Sha256Finalize { ctx_handle, out } => {
            // Transition context to BUSY
            if !context_table.set_busy(*ctx_handle) {
                return OpOutput::Unit(Err(CryptoError::HardwareError));
            }

            let ctx = unsafe { context_table.ctx_mut(*ctx_handle) };
            let exec_fut = driver.sha256_finalize(ctx, unsafe { &mut **out });
            let mut exec_fut = core::pin::pin!(exec_fut);

            let result = core::future::poll_fn(|cx| {
                loop {
                    if op_table.is_cancelled(handle) {
                        context_table.free(*ctx_handle);
                        return Poll::Ready(Err(CryptoError::HardwareError));
                    }
                    match exec_fut.as_mut().poll(cx) {
                        Poll::Pending => {
                            op_table.register_waker(handle, cx.waker());
                            if op_table.is_cancelled(handle) {
                                continue;
                            }
                            return Poll::Pending;
                        }
                        Poll::Ready(result) => {
                            if op_table.is_cancelled(handle) {
                                context_table.free(*ctx_handle);
                                return Poll::Ready(Err(CryptoError::HardwareError));
                            }
                            return Poll::Ready(result);
                        }
                    }
                }
            })
            .await;

            drop(exec_fut);
            context_table.free(*ctx_handle);
            OpOutput::Unit(result)
        }
        _ => unreachable!(),
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
}

/// Object-safe backend used by `CryptoServer`.
pub(crate) trait RunnerBackend {
    fn try_blocking(
        &self,
        required: Capabilities,
        f: &mut dyn FnMut(&mut dyn BlockingCryptoDriver) -> Result<(), CryptoError>,
    ) -> Option<Result<(), CryptoError>>;

    fn try_blocking_size(
        &self,
        required: Capabilities,
        f: &mut dyn FnMut(&mut dyn BlockingCryptoDriver) -> Result<usize, CryptoError>,
    ) -> Option<Result<usize, CryptoError>>;

    fn try_sha256_init(&self) -> Result<ContextHandle, CryptoError>;

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

    fn schedule_sha256_update(
        &self,
        ctx: ContextHandle,
        data: *const [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_sha256_finalize(
        &self,
        ctx: ContextHandle,
        out: *mut [u8; 32],
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

    fn schedule_aes_ccm_128_encrypt(
        &self,
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        plaintext: *const [u8],
        ciphertext: *mut [u8],
        tag: *mut [u8; 16],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_aes_ccm_128_decrypt(
        &self,
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        ciphertext: *const [u8],
        plaintext: *mut [u8],
        tag: *const [u8; 16],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_aes_ccm8_128_encrypt(
        &self,
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        plaintext: *const [u8],
        ciphertext: *mut [u8],
        tag: *mut [u8; 8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_aes_ccm8_128_decrypt(
        &self,
        key: *const [u8; 16],
        nonce: *const [u8],
        aad: *const [u8],
        ciphertext: *const [u8],
        plaintext: *mut [u8],
        tag: *const [u8; 8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_p384_keygen(
        &self,
        secret_key: *mut [u8; 48],
        public_key: *mut [u8; 96],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_p384_ecdh(
        &self,
        secret_key: *const [u8; 48],
        public_key: *const [u8; 96],
        shared_secret: *mut [u8; 48],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_p384_ecdsa_sign(
        &self,
        secret_key: *const [u8; 48],
        digest: *const [u8; 48],
        signature: *mut [u8; 96],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_p384_ecdsa_verify(
        &self,
        public_key: *const [u8; 96],
        digest: *const [u8; 48],
        signature: *const [u8; 96],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_sign_pkcs1v15_sha256(
        &self,
        private_key: *const [u8],
        digest: *const [u8; 32],
        signature: *mut [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_verify_pkcs1v15_sha256(
        &self,
        public_key: *const [u8],
        digest: *const [u8; 32],
        signature: *const [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_sign_pkcs1v15_sha384(
        &self,
        private_key: *const [u8],
        digest: *const [u8; 48],
        signature: *mut [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_verify_pkcs1v15_sha384(
        &self,
        public_key: *const [u8],
        digest: *const [u8; 48],
        signature: *const [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_sign_pkcs1v15_sha512(
        &self,
        private_key: *const [u8],
        digest: *const [u8; 64],
        signature: *mut [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_verify_pkcs1v15_sha512(
        &self,
        public_key: *const [u8],
        digest: *const [u8; 64],
        signature: *const [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_sign_pss_sha256(
        &self,
        private_key: *const [u8],
        digest: *const [u8; 32],
        signature: *mut [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_verify_pss_sha256(
        &self,
        public_key: *const [u8],
        digest: *const [u8; 32],
        signature: *const [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_sign_pss_sha384(
        &self,
        private_key: *const [u8],
        digest: *const [u8; 48],
        signature: *mut [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_verify_pss_sha384(
        &self,
        public_key: *const [u8],
        digest: *const [u8; 48],
        signature: *const [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_sign_pss_sha512(
        &self,
        private_key: *const [u8],
        digest: *const [u8; 64],
        signature: *mut [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn schedule_rsa_verify_pss_sha512(
        &self,
        public_key: *const [u8],
        digest: *const [u8; 64],
        signature: *const [u8],
    ) -> Result<OpHandle, CryptoError>;

    fn poll_op(&self, handle: OpHandle, cx: &mut Context<'_>) -> Poll<OpOutput>;
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
                    context_table: ContextTable::new(),
                }
            }

            /// Run all driver workers concurrently.
            ///
            /// This method never returns.
            #[allow(unreachable_code)]
            pub async fn run(&self) -> ! {
                join_n!(
                    $(driver_worker(self.drivers.$idx, &self.driver_slots[$idx], &self.op_table, &self.context_table, $idx)),+
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

            fn try_blocking_size(
                &self,
                required: Capabilities,
                f: &mut dyn FnMut(&mut dyn BlockingCryptoDriver) -> Result<usize, CryptoError>,
            ) -> Option<Result<usize, CryptoError>> {
                $({
                    if let Ok(mut guard) = self.drivers.$idx.try_lock() {
                        if guard.capabilities().contains(required) {
                            return Some(f(&mut *guard));
                        }
                    }
                })+
                None
            }

            fn try_sha256_init(&self) -> Result<ContextHandle, CryptoError> {
                let handle = self.context_table.alloc()
                    .ok_or(CryptoError::HardwareError)?;

                $({
                    if let Ok(mut guard) = self.drivers.$idx.try_lock() {
                        if guard.capabilities().contains(Capabilities::SHA_256) {
                            let ctx = unsafe { self.context_table.ctx_mut(handle) };
                            guard.blocking_sha256_init(ctx)?;
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

            fn schedule_sha256_update(
                &self,
                ctx: ContextHandle,
                data: *const [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::Sha256Update { ctx_handle: ctx, data };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                // Wake the specific driver that owns this context.
                let driver_idx = unsafe { self.context_table.driver_idx(ctx) };
                self.driver_slots[driver_idx].waker.wake();
                Ok(handle)
            }

            fn schedule_sha256_finalize(
                &self,
                ctx: ContextHandle,
                out: *mut [u8; 32],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::Sha256Finalize { ctx_handle: ctx, out };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                // Wake the specific driver that owns this context.
                let driver_idx = unsafe { self.context_table.driver_idx(ctx) };
                self.driver_slots[driver_idx].waker.wake();
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

            fn schedule_aes_ccm_128_encrypt(
                &self,
                key: *const [u8; 16],
                nonce: *const [u8],
                aad: *const [u8],
                plaintext: *const [u8],
                ciphertext: *mut [u8],
                tag: *mut [u8; 16],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::AesCcm128Encrypt { key, nonce, aad, plaintext, ciphertext, tag };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::AES_128_CCM, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_aes_ccm_128_decrypt(
                &self,
                key: *const [u8; 16],
                nonce: *const [u8],
                aad: *const [u8],
                ciphertext: *const [u8],
                plaintext: *mut [u8],
                tag: *const [u8; 16],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::AesCcm128Decrypt { key, nonce, aad, ciphertext, plaintext, tag };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::AES_128_CCM, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_aes_ccm8_128_encrypt(
                &self,
                key: *const [u8; 16],
                nonce: *const [u8],
                aad: *const [u8],
                plaintext: *const [u8],
                ciphertext: *mut [u8],
                tag: *mut [u8; 8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::AesCcm8_128Encrypt { key, nonce, aad, plaintext, ciphertext, tag };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::AES_128_CCM8, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_aes_ccm8_128_decrypt(
                &self,
                key: *const [u8; 16],
                nonce: *const [u8],
                aad: *const [u8],
                ciphertext: *const [u8],
                plaintext: *mut [u8],
                tag: *const [u8; 8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::AesCcm8_128Decrypt { key, nonce, aad, ciphertext, plaintext, tag };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::AES_128_CCM8, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_p384_keygen(
                &self,
                secret_key: *mut [u8; 48],
                public_key: *mut [u8; 96],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::P384Keygen { secret_key, public_key };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::P384_KEYGEN, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_p384_ecdh(
                &self,
                secret_key: *const [u8; 48],
                public_key: *const [u8; 96],
                shared_secret: *mut [u8; 48],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::P384Ecdh { secret_key, public_key, shared_secret };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::P384_ECDH, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_p384_ecdsa_sign(
                &self,
                secret_key: *const [u8; 48],
                digest: *const [u8; 48],
                signature: *mut [u8; 96],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::P384EcdsaSign { secret_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::P384_ECDSA_SIGN, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_p384_ecdsa_verify(
                &self,
                public_key: *const [u8; 96],
                digest: *const [u8; 48],
                signature: *const [u8; 96],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::P384EcdsaVerify { public_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::P384_ECDSA_VERIFY, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_sign_pkcs1v15_sha256(
                &self,
                private_key: *const [u8],
                digest: *const [u8; 32],
                signature: *mut [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaSignPkcs1v15Sha256 { private_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PKCS1V15_SHA256, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_verify_pkcs1v15_sha256(
                &self,
                public_key: *const [u8],
                digest: *const [u8; 32],
                signature: *const [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaVerifyPkcs1v15Sha256 { public_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PKCS1V15_SHA256, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_sign_pkcs1v15_sha384(
                &self,
                private_key: *const [u8],
                digest: *const [u8; 48],
                signature: *mut [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaSignPkcs1v15Sha384 { private_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PKCS1V15_SHA384, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_verify_pkcs1v15_sha384(
                &self,
                public_key: *const [u8],
                digest: *const [u8; 48],
                signature: *const [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaVerifyPkcs1v15Sha384 { public_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PKCS1V15_SHA384, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_sign_pkcs1v15_sha512(
                &self,
                private_key: *const [u8],
                digest: *const [u8; 64],
                signature: *mut [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaSignPkcs1v15Sha512 { private_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PKCS1V15_SHA512, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_verify_pkcs1v15_sha512(
                &self,
                public_key: *const [u8],
                digest: *const [u8; 64],
                signature: *const [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaVerifyPkcs1v15Sha512 { public_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PKCS1V15_SHA512, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_sign_pss_sha256(
                &self,
                private_key: *const [u8],
                digest: *const [u8; 32],
                signature: *mut [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaSignPssSha256 { private_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PSS_SHA256, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_verify_pss_sha256(
                &self,
                public_key: *const [u8],
                digest: *const [u8; 32],
                signature: *const [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaVerifyPssSha256 { public_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PSS_SHA256, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_sign_pss_sha384(
                &self,
                private_key: *const [u8],
                digest: *const [u8; 48],
                signature: *mut [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaSignPssSha384 { private_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PSS_SHA384, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_verify_pss_sha384(
                &self,
                public_key: *const [u8],
                digest: *const [u8; 48],
                signature: *const [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaVerifyPssSha384 { public_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PSS_SHA384, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_sign_pss_sha512(
                &self,
                private_key: *const [u8],
                digest: *const [u8; 64],
                signature: *mut [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaSignPssSha512 { private_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PSS_SHA512, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn schedule_rsa_verify_pss_sha512(
                &self,
                public_key: *const [u8],
                digest: *const [u8; 64],
                signature: *const [u8],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::RsaVerifyPssSha512 { public_key, digest, signature };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                wake_capable(Capabilities::RSA_PSS_SHA512, &self.driver_slots, self.num_drivers);
                Ok(handle)
            }

            fn poll_op(&self, handle: OpHandle, cx: &mut Context<'_>) -> Poll<OpOutput> {
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
