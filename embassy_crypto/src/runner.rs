use core::task::{Context, Poll};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;

use embassy_crypto_driver::{BlockingCryptoDriver, Capabilities, CryptoDriver, CryptoError};

use crate::queue::{OpHandle, OpTable};

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

/// Hardware crypto multiplexer.
///
/// `Drivers` is a tuple of `&Mutex<CriticalSectionRawMutex, D>` references.
/// `Q` is the queue capacity. `T` is the maximum number of in-flight ops.
pub struct CryptoRunner<Drivers, const Q: usize, const T: usize> {
    drivers: Drivers,
    queue: Channel<CriticalSectionRawMutex, OpHandle, Q>,
    op_table: OpTable<T>,
}

impl<Drivers, const Q: usize, const T: usize> CryptoRunner<Drivers, Q, T> {
    pub fn new(drivers: Drivers) -> Self {
        Self {
            drivers,
            queue: Channel::new(),
            op_table: OpTable::new(),
        }
    }
}

/// Per-driver worker future. Pulls operations from the shared queue and
/// executes them on the given driver.
async fn driver_worker<'a, D: CryptoDriver, const Q: usize, const T: usize>(
    driver: &'a Mutex<CriticalSectionRawMutex, D>,
    queue: &'a Channel<CriticalSectionRawMutex, OpHandle, Q>,
    op_table: &'a OpTable<T>,
) -> ! {
    let driver_caps = driver.lock().await.capabilities();

    loop {
        let handle = queue.receive().await;
        let kind = unsafe { op_table.kind(handle) };
        let caps = kind.required_caps();

        if !driver_caps.contains(caps) {
            // Re-enqueue so a capable worker can pick it up.
            if queue.try_send(handle).is_err() {
                op_table.complete(handle, Err(CryptoError::HardwareError));
            }
            embassy_futures::yield_now().await;
            continue;
        }

        if !op_table.claim_for_run(handle) {
            // Slot was cancelled before we got to it.
            continue;
        }

        let mut guard = driver.lock().await;
        let result = unsafe { kind.execute(&mut *guard).await };
        op_table.complete(handle, result);
    }
}

/// Object-safe backend used by `CryptoServer`.
///
/// This trait bridges the type-erased server to the concrete runner.
/// It is crate-private; users interact with `CryptoServer` instead.
pub(crate) trait RunnerBackend {
    /// Try to execute a blocking operation on the first available driver.
    fn try_blocking(
        &self,
        required: Capabilities,
        f: &mut dyn FnMut(&mut dyn BlockingCryptoDriver) -> Result<(), CryptoError>,
    ) -> Option<Result<(), CryptoError>>;

    // ------------------------------------------------------------------
    // Scheduling
    // ------------------------------------------------------------------
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

    // ------------------------------------------------------------------
    // Polling / cancellation
    // ------------------------------------------------------------------
    fn poll_op(&self, handle: OpHandle, cx: &mut Context<'_>) -> Poll<Result<(), CryptoError>>;
    fn cancel_op(&self, handle: OpHandle) -> Result<(), CryptoError>;
}

macro_rules! impl_crypto_runner {
    ($($idx:tt => $T:ident),+) => {
        impl<'a, $($T: CryptoDriver),+, const Q: usize, const T: usize> CryptoRunner<
            ($(&'a Mutex<CriticalSectionRawMutex, $T>,)+),
            Q,
            T,
        > {
            /// Run all driver workers concurrently.
            ///
            /// This method never returns.
            #[allow(unreachable_code)]
            pub async fn run(&self) -> ! {
                join_n!(
                    $(driver_worker(self.drivers.$idx, &self.queue, &self.op_table)),+
                ).await;

                unreachable!();
            }

            /// Obtain a type-erased server handle.
            pub fn server(&self) -> crate::server::CryptoServer<'_> {
                crate::server::CryptoServer { backend: self }
            }
        }

        impl<'a, $($T: CryptoDriver),+, const Q: usize, const T: usize> RunnerBackend
            for CryptoRunner<($(&'a Mutex<CriticalSectionRawMutex, $T>,)+), Q, T>
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
                self.queue.try_send(handle).map_err(|_| {
                    self.op_table.free(handle);
                    CryptoError::HardwareError
                })?;
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
                self.queue.try_send(handle).map_err(|_| {
                    self.op_table.free(handle);
                    CryptoError::HardwareError
                })?;
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
                self.queue.try_send(handle).map_err(|_| {
                    self.op_table.free(handle);
                    CryptoError::HardwareError
                })?;
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
                self.queue.try_send(handle).map_err(|_| {
                    self.op_table.free(handle);
                    CryptoError::HardwareError
                })?;
                Ok(handle)
            }

            fn schedule_sha_256(
                &self,
                data: *const [u8],
                out: *mut [u8; 32],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::Sha256 { data, out };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                self.queue.try_send(handle).map_err(|_| {
                    self.op_table.free(handle);
                    CryptoError::HardwareError
                })?;
                Ok(handle)
            }

            fn schedule_sha_384(
                &self,
                data: *const [u8],
                out: *mut [u8; 48],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::Sha384 { data, out };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                self.queue.try_send(handle).map_err(|_| {
                    self.op_table.free(handle);
                    CryptoError::HardwareError
                })?;
                Ok(handle)
            }

            fn schedule_p256_keygen(
                &self,
                secret_key: *mut [u8; 32],
                public_key: *mut [u8; 64],
            ) -> Result<OpHandle, CryptoError> {
                let kind = crate::queue::OpKind::P256Keygen { secret_key, public_key };
                let handle = self.op_table.alloc(kind).ok_or(CryptoError::HardwareError)?;
                self.queue.try_send(handle).map_err(|_| {
                    self.op_table.free(handle);
                    CryptoError::HardwareError
                })?;
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
                self.queue.try_send(handle).map_err(|_| {
                    self.op_table.free(handle);
                    CryptoError::HardwareError
                })?;
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
                self.queue.try_send(handle).map_err(|_| {
                    self.op_table.free(handle);
                    CryptoError::HardwareError
                })?;
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
                self.queue.try_send(handle).map_err(|_| {
                    self.op_table.free(handle);
                    CryptoError::HardwareError
                })?;
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
