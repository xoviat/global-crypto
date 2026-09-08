//! End-to-end canary: a self-contained software driver for `embassy-crypto`'s
//! SHA-256 and HMAC-SHA-256, registered from this test, serving
//! `accelerated-crypto`'s RustCrypto trait wrappers.
//!
//! Run with: cargo test --test sha256
//!
//! The driver below is a plain software SHA-256 (FIPS 180-4) written out in
//! this file on purpose: the test proves the whole chain — RustCrypto trait
//! -> accelerated-crypto wrapper -> embassy-crypto type -> link-time driver —
//! without pulling in any RustCrypto implementation crate.

use accelerated_crypto::{HmacSha256, Sha256};
use digest::{Digest, KeyInit, Mac};

// ===========================================================================
// Mini SHA-256 (software, test-only driver)
// ===========================================================================

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Hash state. Sized to fit `embassy-crypto`'s default opaque driver
/// context (128 bytes on 64-bit targets).
#[derive(Clone)]
struct Sha256Ctx {
    state: [u32; 8],
    len: u64,
    buf: [u8; 64],
}

impl Drop for Sha256Ctx {
    fn drop(&mut self) {}
}

fn sha256_compress(state: &mut [u32; 8], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn sha256_init() -> Sha256Ctx {
    Sha256Ctx {
        state: [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ],
        len: 0,
        buf: [0u8; 64],
    }
}

fn sha256_update(ctx: &mut Sha256Ctx, mut data: &[u8]) {
    ctx.len = ctx.len.wrapping_add(data.len() as u64);
    // Number of bytes already in buf (before this call):
    let prev_len = ctx.len as usize - data.len();
    let mut start = prev_len % 64;

    while !data.is_empty() {
        let take = (64 - start).min(data.len());
        ctx.buf[start..start + take].copy_from_slice(&data[..take]);
        start += take;
        data = &data[take..];
        if start == 64 {
            let block = ctx.buf;
            sha256_compress(&mut ctx.state, &block);
            start = 0;
        }
    }
}

fn sha256_finalize(mut ctx: Sha256Ctx, out: &mut [u8; 32]) {
    let bit_len = ctx.len.wrapping_mul(8);
    let prev_len = ctx.len as usize;
    let start = prev_len % 64;

    ctx.buf[start] = 0x80;
    if start + 1 > 56 {
        for b in &mut ctx.buf[start + 1..] {
            *b = 0;
        }
        let block = ctx.buf;
        sha256_compress(&mut ctx.state, &block);
        ctx.buf = [0u8; 64];
    } else {
        for b in &mut ctx.buf[start + 1..56] {
            *b = 0;
        }
    }
    ctx.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
    let block = ctx.buf;
    sha256_compress(&mut ctx.state, &block);

    for (i, word) in ctx.state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
}

// ===========================================================================
// Driver registration
// ===========================================================================

struct SwSha256;

impl embassy_crypto::driver::Sha256 for SwSha256 {
    type Context = Sha256Ctx;

    fn init() -> Self::Context {
        sha256_init()
    }

    fn update(ctx: &mut Self::Context, data: &[u8]) {
        sha256_update(ctx, data);
    }

    fn finalize(ctx: Self::Context, out: &mut [u8; 32]) {
        sha256_finalize(ctx, out);
    }
}

embassy_crypto::sha256_impl!(SwSha256);

struct SwHmacSha256;

impl embassy_crypto::driver::HmacSha256 for SwHmacSha256 {
    type Context = SwHmacCtx;

    fn init(key: &[u8]) -> Self::Context {
        let mut k = [0u8; 64];
        if key.len() > 64 {
            let mut h = sha256_init();
            sha256_update(&mut h, key);
            let mut digest = [0u8; 32];
            sha256_finalize(h, &mut digest);
            k[..32].copy_from_slice(&digest);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= k[i];
            opad[i] ^= k[i];
        }
        let mut inner = sha256_init();
        sha256_update(&mut inner, &ipad);
        SwHmacCtx { inner, opad }
    }

    fn update(ctx: &mut Self::Context, data: &[u8]) {
        sha256_update(&mut ctx.inner, data);
    }

    fn finalize(ctx: Self::Context, out: &mut [u8; 32]) {
        let mut inner_digest = [0u8; 32];
        sha256_finalize(ctx.inner.clone(), &mut inner_digest);
        let mut outer = sha256_init();
        sha256_update(&mut outer, &ctx.opad);
        sha256_update(&mut outer, &inner_digest);
        sha256_finalize(outer, out);
    }
}

struct SwHmacCtx {
    inner: Sha256Ctx,
    opad: [u8; 64],
}

impl Clone for SwHmacCtx {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            opad: self.opad,
        }
    }
}

impl Drop for SwHmacCtx {
    fn drop(&mut self) {}
}

embassy_crypto::hmac_sha256_impl!(SwHmacSha256);

// ===========================================================================
// Tests: known-answer vectors through the RustCrypto traits
// ===========================================================================

#[test]
fn sha256_digest_trait() {
    // FIPS 180-4 example.
    assert_eq!(
        Sha256::digest(b"abc").as_slice(),
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
            0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
            0x15, 0xad,
        ][..]
    );

    // Multi-block message (FIPS 180-4 second example).
    let expected: [u8; 32] = [
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60,
        0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb,
        0x06, 0xc1,
    ];
    assert_eq!(
        Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").as_slice(),
        &expected[..]
    );
}

#[test]
fn hmac_sha256_mac_trait() {
    // RFC 4231 test case 1.
    let mut mac = HmacSha256::new_from_slice(&[0x0b; 20]).unwrap();
    mac.update(b"Hi There");
    assert_eq!(
        mac.finalize().into_bytes().as_slice(),
        &[
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
            0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
            0xcf, 0xf7,
        ][..]
    );

    // RFC 4231 test case 2.
    let mut mac = HmacSha256::new_from_slice(b"Jefe").unwrap();
    mac.update(b"what do ya want for nothing?");
    let tag = mac.finalize();
    assert_eq!(
        tag.into_bytes().as_slice(),
        &[
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
            0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
        ][..]
    );
}
