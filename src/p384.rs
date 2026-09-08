//! NIST P-384 (secp384r1), accelerated.
//!
//! Scalar multiplication, inversion and `k1*P1 + k2*P2` are delegated to the
//! P-384 arithmetic driver of `embassy-crypto` (link-time pluggable: a HAL
//! accelerator or a software driver). Everything else — scalar field
//! arithmetic, point addition/doubling, encoding, validation — runs in
//! software via the `p384` crate.

use elliptic_curve::bigint::U384;
use p384::elliptic_curve;

use crate::ec::{self, Accelerated, Backend};

/// NIST P-384 elliptic curve, accelerated.
pub type NistP384 = Accelerated<p384::NistP384>;

/// Scalar field element modulo the P-384 curve order.
pub type Scalar = ec::Scalar<p384::NistP384>;

/// Point on the P-384 curve in affine coordinates.
pub type AffinePoint = ec::AffinePoint<p384::NistP384>;

/// Point on the P-384 curve in projective coordinates.
pub type ProjectivePoint = ec::ProjectivePoint<p384::NistP384>;

/// Blinded scalar.
pub type BlindedScalar = elliptic_curve::scalar::BlindedScalar<NistP384>;

/// Compressed SEC1-encoded P-384 curve point.
pub type CompressedPoint = elliptic_curve::sec1::CompressedPoint<NistP384>;

/// SEC1-encoded P-384 curve point.
pub type EncodedPoint = elliptic_curve::sec1::Sec1Point<NistP384>;

/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = elliptic_curve::FieldBytes<NistP384>;

/// Non-zero P-384 scalar field element.
pub type NonZeroScalar = elliptic_curve::NonZeroScalar<NistP384>;

/// P-384 public key.
pub type PublicKey = elliptic_curve::PublicKey<NistP384>;

/// P-384 secret key.
pub type SecretKey = elliptic_curve::SecretKey<NistP384>;

/// ECDSA over P-384.
#[cfg(feature = "p384-ecdsa")]
pub mod ecdsa {
    use super::NistP384;

    /// ECDSA/P-384 signature (fixed-size).
    pub type Signature = ecdsa::Signature<NistP384>;

    /// ECDSA/P-384 signing key.
    pub type SigningKey = ecdsa::SigningKey<NistP384>;

    /// ECDSA/P-384 verification key (i.e. public key).
    pub type VerifyingKey = ecdsa::VerifyingKey<NistP384>;
}

impl From<Scalar> for U384 {
    fn from(scalar: Scalar) -> Self {
        U384::from(scalar.into_inner())
    }
}

impl From<&Scalar> for U384 {
    fn from(scalar: &Scalar) -> Self {
        U384::from(scalar.into_inner())
    }
}

impl Backend for p384::NistP384 {
    const AFFINE_IDENTITY: p384::AffinePoint = p384::AffinePoint::IDENTITY;
    const AFFINE_GENERATOR: p384::AffinePoint = p384::AffinePoint::GENERATOR;

    // These operations are served by `embassy-crypto`'s P-384 arithmetic
    // driver; whether they run on hardware is decided by which driver crate
    // is linked in, not here.
    const ACCELERATED_MUL: bool = true;
    const ACCELERATED_INVERT: bool = true;
    const ACCELERATED_LINCOMB: bool = true;

    fn mul_base(k: &FieldBytes) -> (FieldBytes, FieldBytes) {
        let k = backend_scalar(k);
        point_from_backend(embassy_crypto::p384::Point::mul_base(&k))
    }

    fn mul_affine(k: &FieldBytes, x: &FieldBytes, y: &FieldBytes) -> (FieldBytes, FieldBytes) {
        let p = backend_point(x, y);
        point_from_backend(p.mul(&backend_scalar(k)))
    }

    fn invert(k: &FieldBytes) -> FieldBytes {
        backend_scalar(k)
            .invert()
            .expect("invert of zero scalar")
            .to_bytes()
            .into()
    }

    fn invert_vartime(k: &FieldBytes) -> FieldBytes {
        // The `embassy-crypto` backend exposes a single, constant-time
        // inversion; it is used for both entry points.
        backend_scalar(k)
            .invert()
            .expect("invert of zero scalar")
            .to_bytes()
            .into()
    }

    fn lincomb(
        k1: &FieldBytes,
        x1: &FieldBytes,
        y1: &FieldBytes,
        k2: &FieldBytes,
        x2: &FieldBytes,
        y2: &FieldBytes,
    ) -> Option<(FieldBytes, FieldBytes)> {
        let sum = embassy_crypto::p384::Point::lincomb_vartime(
            &backend_scalar(k1),
            &backend_point(x1, y1),
            &backend_scalar(k2),
            &backend_point(x2, y2),
        );

        point_from_backend_opt(sum)
    }
}

fn backend_scalar(k: &FieldBytes) -> embassy_crypto::p384::Scalar {
    embassy_crypto::p384::Scalar::from_bytes(k.as_slice().try_into().unwrap())
        .expect("scalar not in range")
}

fn backend_point(x: &FieldBytes, y: &FieldBytes) -> embassy_crypto::p384::Point {
    embassy_crypto::p384::Point::from_xy(
        x.as_slice().try_into().unwrap(),
        y.as_slice().try_into().unwrap(),
    )
    .expect("point not on curve")
}

/// Map a backend point back to coordinates, with the all-zero sentinel for
/// the point at infinity (see `ec::point_from_driver`).
fn point_from_backend(p: embassy_crypto::p384::Point) -> (FieldBytes, FieldBytes) {
    match p.to_affine() {
        Some(a) => (a.x.into(), a.y.into()),
        None => (FieldBytes::default(), FieldBytes::default()),
    }
}

/// Like [`point_from_backend`], but reporting the identity as `None`, per
/// the `lincomb` driver contract.
fn point_from_backend_opt(p: embassy_crypto::p384::Point) -> Option<(FieldBytes, FieldBytes)> {
    p.to_affine().map(|a| (a.x.into(), a.y.into()))
}
