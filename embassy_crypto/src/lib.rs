#![no_std]

mod queue;
mod runner;
mod server;

// Re-export driver crate for convenience so users need only one dependency.
pub use embassy_crypto_driver::*;

// Public API
pub use runner::CryptoRunner;
pub use server::CryptoServer;

#[cfg(test)]
mod mock {
    use core::future::Future;
    use embassy_crypto_driver::{BlockingCryptoDriver, Capabilities, CryptoDriver, CryptoError};

    #[derive(Default)]
    pub struct MockDriver {
        pub caps: Capabilities,
        pub fail_next: bool,
    }

    impl BlockingCryptoDriver for MockDriver {
        fn capabilities(&self) -> Capabilities {
            self.caps
        }

        fn rng_fill(&mut self, _dest: &mut [u8]) -> Result<(), CryptoError> {
            if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
        }

        fn aes_128_ecb_encrypt(
            &mut self,
            _block: &mut [u8; 16],
            _key: &[u8; 16],
        ) -> Result<(), CryptoError> {
            if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
        }

        fn aes_128_ecb_decrypt(
            &mut self,
            _block: &mut [u8; 16],
            _key: &[u8; 16],
        ) -> Result<(), CryptoError> {
            if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
        }

        fn aes_128_cmac(
            &mut self,
            _key: &[u8; 16],
            _data: &[u8],
            _out: &mut [u8; 16],
        ) -> Result<(), CryptoError> {
            if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
        }
    }

    impl CryptoDriver for MockDriver {
        fn aes_gcm_128_encrypt<'a>(
            &'a mut self,
            _key: &'a [u8; 16],
            _nonce: &'a [u8],
            _aad: &'a [u8],
            _plaintext: &'a [u8],
            _ciphertext: &'a mut [u8],
            _tag: &'a mut [u8; 16],
        ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
            async move {
                if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
            }
        }

        fn aes_gcm_128_decrypt<'a>(
            &'a mut self,
            _key: &'a [u8; 16],
            _nonce: &'a [u8],
            _aad: &'a [u8],
            _ciphertext: &'a [u8],
            _plaintext: &'a mut [u8],
            _tag: &'a [u8; 16],
        ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
            async move {
                if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
            }
        }

        fn aes_gcm_256_encrypt<'a>(
            &'a mut self,
            _key: &'a [u8; 32],
            _nonce: &'a [u8],
            _aad: &'a [u8],
            _plaintext: &'a [u8],
            _ciphertext: &'a mut [u8],
            _tag: &'a mut [u8; 16],
        ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
            async move {
                if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
            }
        }

        fn aes_gcm_256_decrypt<'a>(
            &'a mut self,
            _key: &'a [u8; 32],
            _nonce: &'a [u8],
            _aad: &'a [u8],
            _ciphertext: &'a [u8],
            _plaintext: &'a mut [u8],
            _tag: &'a [u8; 16],
        ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
            async move {
                if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
            }
        }

        fn sha_256<'a>(
            &'a mut self,
            _data: &'a [u8],
            _out: &'a mut [u8; 32],
        ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
            async move {
                if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
            }
        }

        fn sha_384<'a>(
            &'a mut self,
            _data: &'a [u8],
            _out: &'a mut [u8; 48],
        ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
            async move {
                if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
            }
        }

        fn p256_keygen<'a>(
            &'a mut self,
            _secret_key: &'a mut [u8; 32],
            _public_key: &'a mut [u8; 64],
        ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
            async move {
                if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
            }
        }

        fn p256_ecdh<'a>(
            &'a mut self,
            _secret_key: &'a [u8; 32],
            _public_key: &'a [u8; 64],
            _shared_secret: &'a mut [u8; 32],
        ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
            async move {
                if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
            }
        }

        fn p256_ecdsa_sign<'a>(
            &'a mut self,
            _secret_key: &'a [u8; 32],
            _digest: &'a [u8; 32],
            _signature: &'a mut [u8; 64],
        ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
            async move {
                if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
            }
        }

        fn p256_ecdsa_verify<'a>(
            &'a mut self,
            _public_key: &'a [u8; 64],
            _digest: &'a [u8; 32],
            _signature: &'a [u8; 64],
        ) -> impl Future<Output = Result<(), CryptoError>> + 'a {
            async move {
                if self.fail_next { Err(CryptoError::HardwareError) } else { Ok(()) }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
    use embassy_sync::mutex::Mutex;

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker { noop_raw_waker() }
        unsafe fn noop(_: *const ()) {}
        fn noop_raw_waker() -> RawWaker {
            RawWaker::new(core::ptr::null(), &RawWakerVTable::new(clone, noop, noop, noop))
        }
        unsafe { Waker::from_raw(noop_raw_waker()) }
    }

    fn ctx() -> Context<'static> {
        Context::from_waker(&noop_waker())
    }

    // ------------------------------------------------------------------
    // OpTable tests
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn op_table_alloc_and_free() {
        let table = queue::OpTable::<4>::new();
        let kind = queue::OpKind::Sha256 {
            data: core::ptr::null(),
            out: core::ptr::null_mut(),
        };
        let h = table.alloc(kind).unwrap();
        table.free(h);
        // Should be able to allocate again after free.
        let _ = table.alloc(kind).unwrap();
    }

    #[tokio::test]
    async fn op_table_alloc_exhausted() {
        let table = queue::OpTable::<2>::new();
        let kind = queue::OpKind::Sha256 {
            data: core::ptr::null(),
            out: core::ptr::null_mut(),
        };
        let _h0 = table.alloc(kind).unwrap();
        let _h1 = table.alloc(kind).unwrap();
        assert!(table.alloc(kind).is_none());
    }

    #[tokio::test]
    async fn op_table_complete_and_poll() {
        let table = queue::OpTable::<2>::new();
        let kind = queue::OpKind::Sha256 {
            data: core::ptr::null(),
            out: core::ptr::null_mut(),
        };
        let h = table.alloc(kind).unwrap();
        assert!(table.claim_for_run(h));
        table.complete(h, Ok(()));

        let mut cx = ctx();
        match table.poll(h, &mut cx) {
            Poll::Ready(Ok(())) => {}
            other => panic!("expected Ready(Ok), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn op_table_cancel_pending() {
        let table = queue::OpTable::<2>::new();
        let kind = queue::OpKind::Sha256 {
            data: core::ptr::null(),
            out: core::ptr::null_mut(),
        };
        let h = table.alloc(kind).unwrap();
        table.cancel(h);

        let mut cx = ctx();
        match table.poll(h, &mut cx) {
            Poll::Ready(Err(CryptoError::HardwareError)) => {}
            other => panic!("expected Ready(Err(HardwareError)), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn op_table_cancel_running_is_too_late() {
        let table = queue::OpTable::<2>::new();
        let kind = queue::OpKind::Sha256 {
            data: core::ptr::null(),
            out: core::ptr::null_mut(),
        };
        let h = table.alloc(kind).unwrap();
        assert!(table.claim_for_run(h));
        // Cancel while running does nothing; complete still works.
        table.cancel(h);
        table.complete(h, Ok(()));

        let mut cx = ctx();
        match table.poll(h, &mut cx) {
            Poll::Ready(Ok(())) => {}
            other => panic!("expected Ready(Ok), got {:?}", other),
        }
    }

    // ------------------------------------------------------------------
    // Blocking dispatch tests
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn try_blocking_success() {
        let driver = Mutex::<ThreadModeRawMutex, mock::MockDriver>::new(mock::MockDriver {
            caps: Capabilities::RNG,
            ..Default::default()
        });
        let runner = CryptoRunner::<_, 4, 4>::new((&driver,));
        let server = runner.server();

        let mut buf = [0u8; 16];
        assert!(server.rng_fill(&mut buf).is_ok());
    }

    #[tokio::test]
    async fn try_blocking_skips_busy_driver() {
        let driver = Mutex::<ThreadModeRawMutex, mock::MockDriver>::new(mock::MockDriver {
            caps: Capabilities::RNG,
            ..Default::default()
        });
        // Lock the driver so try_blocking cannot acquire it.
        let _guard = driver.try_lock().unwrap();

        let runner = CryptoRunner::<_, 4, 4>::new((&driver,));
        let server = runner.server();

        let mut buf = [0u8; 16];
        assert_eq!(server.rng_fill(&mut buf), Err(CryptoError::HardwareError));
    }

    #[tokio::test]
    async fn try_blocking_unsupported_capability() {
        let driver = Mutex::<ThreadModeRawMutex, mock::MockDriver>::new(mock::MockDriver {
            caps: Capabilities::AES_128_GCM,
            ..Default::default()
        });
        let runner = CryptoRunner::<_, 4, 4>::new((&driver,));
        let server = runner.server();

        let mut buf = [0u8; 16];
        assert_eq!(server.rng_fill(&mut buf), Err(CryptoError::HardwareError));
    }

    #[tokio::test]
    async fn try_blocking_falls_back_to_second_driver() {
        let driver1 = Mutex::<ThreadModeRawMutex, mock::MockDriver>::new(mock::MockDriver {
            caps: Capabilities::RNG,
            ..Default::default()
        });
        let driver2 = Mutex::<ThreadModeRawMutex, mock::MockDriver>::new(mock::MockDriver {
            caps: Capabilities::RNG,
            ..Default::default()
        });

        // Lock the first driver
        let _guard = driver1.try_lock().unwrap();

        let runner = CryptoRunner::<_, 4, 4>::new((&driver1, &driver2));
        let server = runner.server();

        let mut buf = [0u8; 16];
        assert!(server.rng_fill(&mut buf).is_ok());
    }

    // ------------------------------------------------------------------
    // Async scheduling tests (no spawned runner — manual poll)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn server_future_schedules_on_first_poll() {
        let driver = Mutex::<ThreadModeRawMutex, mock::MockDriver>::new(mock::MockDriver {
            caps: Capabilities::AES_128_GCM,
            ..Default::default()
        });
        let runner = CryptoRunner::<_, 4, 4>::new((&driver,));
        let server = runner.server();

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad: &[u8] = &[];
        let plaintext: &[u8] = &[];
        let mut ciphertext = [0u8; 0];
        let mut tag = [0u8; 16];

        let mut fut = server.aes_gcm_128_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag);
        let mut cx = ctx();
        let r = Pin::new(&mut fut).poll(&mut cx);
        assert!(r.is_pending());
    }

    #[tokio::test]
    async fn server_future_drop_cancels_pending_op() {
        let driver = Mutex::<ThreadModeRawMutex, mock::MockDriver>::new(mock::MockDriver {
            caps: Capabilities::AES_128_GCM,
            ..Default::default()
        });
        let runner = CryptoRunner::<_, 4, 4>::new((&driver,));
        let server = runner.server();

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad: &[u8] = &[];
        let plaintext: &[u8] = &[];
        let mut ciphertext = [0u8; 0];
        let mut tag = [0u8; 16];

        {
            let mut fut = server.aes_gcm_128_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag);
            let mut cx = ctx();
            let _ = Pin::new(&mut fut).poll(&mut cx);
            // fut dropped here → cancel_op called
        }

        // After drop, the slot should be free. Verify by scheduling a new future.
        let mut fut2 = server.aes_gcm_128_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag);
        let mut cx = ctx();
        let r = Pin::new(&mut fut2).poll(&mut cx);
        assert!(r.is_pending());
    }

    #[tokio::test]
    async fn server_future_queue_full() {
        // Queue capacity 1, op table capacity 2.
        let driver = Mutex::<ThreadModeRawMutex, mock::MockDriver>::new(mock::MockDriver {
            caps: Capabilities::AES_128_GCM,
            ..Default::default()
        });
        let runner = CryptoRunner::<_, 1, 2>::new((&driver,));
        let server = runner.server();

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad: &[u8] = &[];
        let plaintext: &[u8] = &[];
        let mut ciphertext = [0u8; 0];
        let mut tag = [0u8; 16];

        let mut fut1 = server.aes_gcm_128_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag);
        let mut cx = ctx();
        let r1 = Pin::new(&mut fut1).poll(&mut cx);
        assert!(r1.is_pending());

        // Queue is now full (capacity 1). Second schedule should fail.
        let mut fut2 = server.aes_gcm_128_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag);
        let r2 = Pin::new(&mut fut2).poll(&mut cx);
        assert!(r2.is_ready());
        assert_eq!(r2, Poll::Ready(Err(CryptoError::HardwareError)));
    }

    // ------------------------------------------------------------------
    // Async integration tests (spawned runner + await)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn async_sha256_success() {
        let driver = Box::leak(Box::new(Mutex::new(mock::MockDriver {
            caps: Capabilities::SHA_256,
            ..Default::default()
        })));
        let runner = Box::leak(Box::new(CryptoRunner::<_, 4, 4>::new((driver,))));
        let server = runner.server();

        tokio::spawn(async move {
            runner.run().await;
        });

        let data = [0u8; 32];
        let mut out = [0u8; 32];
        let result = server.sha_256(&data, &mut out).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn async_aes_gcm_128_encrypt_success() {
        let driver = Box::leak(Box::new(Mutex::new(mock::MockDriver {
            caps: Capabilities::AES_128_GCM,
            ..Default::default()
        })));
        let runner = Box::leak(Box::new(CryptoRunner::<_, 4, 4>::new((driver,))));
        let server = runner.server();

        tokio::spawn(async move {
            runner.run().await;
        });

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad: &[u8] = &[];
        let plaintext: &[u8] = &[];
        let mut ciphertext = [0u8; 0];
        let mut tag = [0u8; 16];

        let result = server.aes_gcm_128_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn async_aes_gcm_128_decrypt_success() {
        let driver = Box::leak(Box::new(Mutex::new(mock::MockDriver {
            caps: Capabilities::AES_128_GCM,
            ..Default::default()
        })));
        let runner = Box::leak(Box::new(CryptoRunner::<_, 4, 4>::new((driver,))));
        let server = runner.server();

        tokio::spawn(async move {
            runner.run().await;
        });

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad: &[u8] = &[];
        let ciphertext: &[u8] = &[];
        let mut plaintext = [0u8; 0];
        let tag = [0u8; 16];

        let result = server.aes_gcm_128_decrypt(&key, &nonce, aad, ciphertext, &mut plaintext, &tag).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn async_p256_ecdsa_sign_success() {
        let driver = Box::leak(Box::new(Mutex::new(mock::MockDriver {
            caps: Capabilities::P256_ECDSA_SIGN,
            ..Default::default()
        })));
        let runner = Box::leak(Box::new(CryptoRunner::<_, 4, 4>::new((driver,))));
        let server = runner.server();

        tokio::spawn(async move {
            runner.run().await;
        });

        let secret_key = [0u8; 32];
        let digest = [0u8; 32];
        let mut signature = [0u8; 64];

        let result = server.p256_ecdsa_sign(&secret_key, &digest, &mut signature).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn async_multiple_ops_sequential() {
        let driver = Box::leak(Box::new(Mutex::new(mock::MockDriver {
            caps: Capabilities::SHA_256 | Capabilities::SHA_384,
            ..Default::default()
        })));
        let runner = Box::leak(Box::new(CryptoRunner::<_, 4, 4>::new((driver,))));
        let server = runner.server();

        tokio::spawn(async move {
            runner.run().await;
        });

        let data = [0u8; 32];
        let mut out256 = [0u8; 32];
        let mut out384 = [0u8; 48];

        let r1 = server.sha_256(&data, &mut out256).await;
        let r2 = server.sha_384(&data, &mut out384).await;
        assert!(r1.is_ok());
        assert!(r2.is_ok());
    }

    #[tokio::test]
    async fn async_driver_returns_error() {
        let driver = Box::leak(Box::new(Mutex::new(mock::MockDriver {
            caps: Capabilities::SHA_256,
            fail_next: true,
        })));
        let runner = Box::leak(Box::new(CryptoRunner::<_, 4, 4>::new((driver,))));
        let server = runner.server();

        tokio::spawn(async move {
            runner.run().await;
        });

        let data = [0u8; 32];
        let mut out = [0u8; 32];
        let result = server.sha_256(&data, &mut out).await;
        assert_eq!(result, Err(CryptoError::HardwareError));
    }

    #[tokio::test]
    async fn async_two_drivers_different_caps() {
        let aes_driver = Box::leak(Box::new(Mutex::new(mock::MockDriver {
            caps: Capabilities::AES_128_GCM,
            ..Default::default()
        })));
        let sha_driver = Box::leak(Box::new(Mutex::new(mock::MockDriver {
            caps: Capabilities::SHA_256,
            ..Default::default()
        })));
        let runner = Box::leak(Box::new(CryptoRunner::<_, 4, 4>::new((aes_driver, sha_driver))));
        let server = runner.server();

        tokio::spawn(async move {
            runner.run().await;
        });

        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let aad: &[u8] = &[];
        let plaintext: &[u8] = &[];
        let mut ciphertext = [0u8; 0];
        let mut tag = [0u8; 16];

        let data = [0u8; 32];
        let mut out = [0u8; 32];

        // AES op goes to aes_driver, SHA op goes to sha_driver
        let r1 = server.aes_gcm_128_encrypt(&key, &nonce, aad, plaintext, &mut ciphertext, &mut tag).await;
        let r2 = server.sha_256(&data, &mut out).await;
        assert!(r1.is_ok());
        assert!(r2.is_ok());
    }
}
