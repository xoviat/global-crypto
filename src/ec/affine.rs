//! Point in affine coordinates.
//!
//! A newtype around the wrapped curve's affine point; every trait is
//! implemented by delegation, except scalar multiplication which goes through
//! the driver.

use core::borrow::Borrow;
use core::fmt;
use core::ops::{Mul, Neg};

use elliptic_curve::bigint::ctutils::{CtEq, CtSelect};
use elliptic_curve::common::Generate;
use elliptic_curve::group::{CurveAffine, GroupEncoding};
use elliptic_curve::ops::MulVartime;
use elliptic_curve::point::{AffineCoordinates, DecompactPoint, DecompressPoint, NonIdentity};
use elliptic_curve::sec1::{CompressedPoint, FromSec1Point, ToCompactSec1Point, ToSec1Point};
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use elliptic_curve::zeroize::DefaultIsZeroes;
use elliptic_curve::{Error, FieldBytes, PublicKey};

use super::{Accelerated, Backend, EncodedPoint, ProjectivePoint, Scalar};

/// Point on the curve in affine coordinates.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct AffinePoint<C: Backend>(pub(crate) C::AffinePoint);

impl<C: Backend> AffinePoint<C> {
    /// Additive identity of the group a.k.a. the point at infinity.
    pub const IDENTITY: Self = Self(C::AFFINE_IDENTITY);

    /// Base point of the curve.
    pub const GENERATOR: Self = Self(C::AFFINE_GENERATOR);

    /// The wrapped curve's point.
    pub fn into_inner(self) -> C::AffinePoint {
        self.0
    }

    /// Wrap the wrapped curve's point.
    pub fn from_inner(point: C::AffinePoint) -> Self {
        Self(point)
    }
}

impl<C: Backend> fmt::Debug for AffinePoint<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<C: Backend> AffineCoordinates for AffinePoint<C> {
    type FieldRepr = FieldBytes<C>;

    fn from_coordinates(x: &FieldBytes<C>, y: &FieldBytes<C>) -> CtOption<Self> {
        <C::AffinePoint as AffineCoordinates>::from_coordinates(x, y).map(Self)
    }

    fn x(&self) -> FieldBytes<C> {
        self.0.x()
    }

    fn y(&self) -> FieldBytes<C> {
        self.0.y()
    }

    fn x_is_odd(&self) -> Choice {
        self.0.x_is_odd()
    }

    fn y_is_odd(&self) -> Choice {
        self.0.y_is_odd()
    }
}

impl<C: Backend> ConditionallySelectable for AffinePoint<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(C::AffinePoint::conditional_select(&a.0, &b.0, choice))
    }
}

impl<C: Backend> ConstantTimeEq for AffinePoint<C> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(&self.0, &other.0)
    }
}

impl<C: Backend> DefaultIsZeroes for AffinePoint<C> {}

impl<C: Backend> DecompressPoint<Accelerated<C>> for AffinePoint<C> {
    fn decompress(x: &FieldBytes<C>, y_is_odd: Choice) -> CtOption<Self> {
        <C::AffinePoint as DecompressPoint<C>>::decompress(x, y_is_odd).map(Self)
    }
}

impl<C: Backend> DecompactPoint<Accelerated<C>> for AffinePoint<C> {
    fn decompact(x: &FieldBytes<C>) -> CtOption<Self> {
        <C::AffinePoint as DecompactPoint<C>>::decompact(x).map(Self)
    }
}

impl<C: Backend> FromSec1Point<Accelerated<C>> for AffinePoint<C> {
    fn from_sec1_point(point: &EncodedPoint<Accelerated<C>>) -> elliptic_curve::bigint::CtOption<Self> {
        let point = EncodedPoint::<C>::from_bytes(point.as_bytes()).expect("same size encoding");
        <C::AffinePoint as FromSec1Point<C>>::from_sec1_point(&point).map(Self)
    }
}

impl<C: Backend> ToSec1Point<Accelerated<C>> for AffinePoint<C> {
    fn to_sec1_point(&self, compress: bool) -> EncodedPoint<C> {
        <C::AffinePoint as ToSec1Point<C>>::to_sec1_point(&self.0, compress)
    }
}

impl<C: Backend> ToCompactSec1Point<Accelerated<C>> for AffinePoint<C> {
    fn to_compact_encoded_point(&self) -> elliptic_curve::bigint::CtOption<EncodedPoint<Accelerated<C>>> {
        <C::AffinePoint as ToCompactSec1Point<C>>::to_compact_encoded_point(&self.0)
            .map(|p| EncodedPoint::<Accelerated<C>>::from_bytes(p.as_bytes()).expect("same size encoding"))
    }
}

impl<C: Backend> From<ProjectivePoint<C>> for AffinePoint<C> {
    fn from(point: ProjectivePoint<C>) -> Self {
        Self(point.affine())
    }
}

impl<C: Backend> From<&ProjectivePoint<C>> for AffinePoint<C> {
    fn from(point: &ProjectivePoint<C>) -> Self {
        Self(point.affine())
    }
}

impl<C: Backend> From<PublicKey<Accelerated<C>>> for AffinePoint<C> {
    fn from(public_key: PublicKey<Accelerated<C>>) -> Self {
        *public_key.as_affine()
    }
}

impl<C: Backend> From<&PublicKey<Accelerated<C>>> for AffinePoint<C> {
    fn from(public_key: &PublicKey<Accelerated<C>>) -> Self {
        *public_key.as_affine()
    }
}

impl<C: Backend> From<AffinePoint<C>> for EncodedPoint<C> {
    fn from(point: AffinePoint<C>) -> Self {
        point.to_sec1_point(C::COMPRESS_POINTS)
    }
}

impl<C: Backend> GroupEncoding for AffinePoint<C> {
    type Repr = CompressedPoint<C>;

    fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
        <C::AffinePoint as GroupEncoding>::from_bytes(bytes).map(Self)
    }

    fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
        <C::AffinePoint as GroupEncoding>::from_bytes_unchecked(bytes).map(Self)
    }

    fn to_bytes(&self) -> Self::Repr {
        <C::AffinePoint as GroupEncoding>::to_bytes(&self.0)
    }
}

impl<C: Backend> CurveAffine for AffinePoint<C> {
    type Curve = ProjectivePoint<C>;
    type Scalar = Scalar<C>;

    fn identity() -> Self {
        Self::IDENTITY
    }

    fn generator() -> Self {
        Self::GENERATOR
    }

    fn is_identity(&self) -> Choice {
        CurveAffine::is_identity(&self.0)
    }

    fn to_curve(&self) -> ProjectivePoint<C> {
        ProjectivePoint::from_affine(self.0)
    }
}

impl<C: Backend> TryFrom<EncodedPoint<C>> for AffinePoint<C> {
    type Error = Error;

    fn try_from(point: EncodedPoint<C>) -> Result<Self, Error> {
        Self::try_from(&point)
    }
}

impl<C: Backend> TryFrom<&EncodedPoint<C>> for AffinePoint<C> {
    type Error = Error;

    fn try_from(point: &EncodedPoint<C>) -> Result<Self, Error> {
        Option::from(Self::from_sec1_point(point)).ok_or(Error)
    }
}

impl<C: Backend> TryFrom<AffinePoint<C>> for PublicKey<Accelerated<C>> {
    type Error = Error;

    fn try_from(point: AffinePoint<C>) -> Result<Self, Error> {
        PublicKey::from_affine(point)
    }
}

impl<C: Backend> TryFrom<&AffinePoint<C>> for PublicKey<Accelerated<C>> {
    type Error = Error;

    fn try_from(point: &AffinePoint<C>) -> Result<Self, Error> {
        PublicKey::from_affine(*point)
    }
}

/// Scalar multiplication, via the driver.
impl<C: Backend, S> Mul<S> for AffinePoint<C>
where
    S: Borrow<Scalar<C>>,
{
    type Output = ProjectivePoint<C>;

    fn mul(self, scalar: S) -> ProjectivePoint<C> {
        super::mul(scalar.borrow(), &self)
    }
}

impl<C: Backend> Neg for AffinePoint<C> {
    type Output = Self;

    fn neg(self) -> Self {
        Self(-self.0)
    }
}

impl<C: Backend> Neg for &AffinePoint<C> {
    type Output = AffinePoint<C>;

    fn neg(self) -> AffinePoint<C> {
        AffinePoint(-self.0)
    }
}

impl<C: Backend> CtEq for AffinePoint<C> {
    fn ct_eq(&self, other: &Self) -> elliptic_curve::bigint::Choice {
        CtEq::ct_eq(&self.0, &other.0)
    }
}

impl<C: Backend> CtSelect for AffinePoint<C> {
    fn ct_select(&self, other: &Self, choice: elliptic_curve::bigint::Choice) -> Self {
        Self(CtSelect::ct_select(&self.0, &other.0, choice))
    }
}

impl<C: Backend> Generate for AffinePoint<C> {
    fn try_generate_from_rng<R: elliptic_curve::rand_core::TryCryptoRng + ?Sized>(
        rng: &mut R,
    ) -> Result<Self, R::Error> {
        C::AffinePoint::try_generate_from_rng(rng).map(Self)
    }
}

impl<C: Backend> From<NonIdentity<Self>> for AffinePoint<C> {
    fn from(nid: NonIdentity<Self>) -> Self {
        nid.to_point()
    }
}

impl<C: Backend> TryFrom<AffinePoint<C>> for NonIdentity<AffinePoint<C>> {
    type Error = elliptic_curve::Error;

    fn try_from(point: AffinePoint<C>) -> Result<Self, Self::Error> {
        Option::from(NonIdentity::new(point)).ok_or(elliptic_curve::Error)
    }
}

impl<C: Backend> MulVartime<Scalar<C>> for AffinePoint<C> {
    fn mul_vartime(self, rhs: Scalar<C>) -> ProjectivePoint<C> {
        super::mul(&rhs, &self)
    }
}

impl<C: Backend> MulVartime<&Scalar<C>> for AffinePoint<C> {
    fn mul_vartime(self, rhs: &Scalar<C>) -> ProjectivePoint<C> {
        super::mul(rhs, &self)
    }
}
