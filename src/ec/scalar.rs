//! Scalar field element (integer modulo the curve order).
//!
//! A newtype around the wrapped curve's scalar; every trait is implemented by
//! delegation, except inversion which may go through the driver.

use core::fmt;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Shr, ShrAssign, Sub, SubAssign};

use elliptic_curve::bigint::RandomMod;
use elliptic_curve::bigint::ctutils::{CtEq, CtSelect};
use elliptic_curve::bigint::modular::Retrieve;
use elliptic_curve::common::Generate;
use elliptic_curve::ff::{Field, PrimeField};
use elliptic_curve::ops::{Invert, MulVartime, Reduce, ReduceNonZero};
use elliptic_curve::rand_core::{TryCryptoRng, TryRng};
use elliptic_curve::scalar::{FromUintUnchecked, IsHigh};
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use elliptic_curve::zeroize::DefaultIsZeroes;
use elliptic_curve::{FieldBytes, ScalarValue, SecretKey};

use super::{Accelerated, AffinePoint, Backend, ProjectivePoint};

/// Scalar field element modulo the curve order.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Scalar<C: Backend>(pub(crate) C::Scalar);

impl<C: Backend> Scalar<C> {
    /// Zero scalar.
    pub const ZERO: Self = Self(<C::Scalar as Field>::ZERO);

    /// Multiplicative identity.
    pub const ONE: Self = Self(<C::Scalar as Field>::ONE);

    /// The wrapped curve's scalar.
    pub fn into_inner(self) -> C::Scalar {
        self.0
    }

    /// Wrap the wrapped curve's scalar.
    pub fn from_inner(scalar: C::Scalar) -> Self {
        Self(scalar)
    }
}

impl<C: Backend> fmt::Debug for Scalar<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<C: Backend> AsRef<Scalar<C>> for Scalar<C> {
    fn as_ref(&self) -> &Scalar<C> {
        self
    }
}

impl<C: Backend> Field for Scalar<C> {
    const ZERO: Self = Self(<C::Scalar as Field>::ZERO);
    const ONE: Self = Self(<C::Scalar as Field>::ONE);

    fn try_random<R: TryRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        <C::Scalar as Field>::try_random(rng).map(Self)
    }

    fn is_zero(&self) -> Choice {
        Field::is_zero(&self.0)
    }

    fn is_zero_vartime(&self) -> bool {
        Field::is_zero_vartime(&self.0)
    }

    fn square(&self) -> Self {
        Self(Field::square(&self.0))
    }

    fn cube(&self) -> Self {
        Self(Field::cube(&self.0))
    }

    fn double(&self) -> Self {
        Self(Field::double(&self.0))
    }

    fn invert(&self) -> CtOption<Self> {
        super::invert(self)
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        let (choice, value) = <C::Scalar as Field>::sqrt_ratio(&num.0, &div.0);
        (choice, Self(value))
    }

    fn sqrt_alt(&self) -> (Choice, Self) {
        let (choice, value) = Field::sqrt_alt(&self.0);
        (choice, Self(value))
    }

    fn sqrt(&self) -> CtOption<Self> {
        Field::sqrt(&self.0).map(Self)
    }

    fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        Self(Field::pow(&self.0, exp))
    }

    fn pow_vartime<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        Self(Field::pow_vartime(&self.0, exp))
    }
}

impl<C: Backend> PrimeField for Scalar<C> {
    type Repr = FieldBytes<C>;

    const MODULUS: &'static str = <C::Scalar as PrimeField>::MODULUS;
    const NUM_BITS: u32 = <C::Scalar as PrimeField>::NUM_BITS;
    const CAPACITY: u32 = <C::Scalar as PrimeField>::CAPACITY;
    const TWO_INV: Self = Self(<C::Scalar as PrimeField>::TWO_INV);
    const MULTIPLICATIVE_GENERATOR: Self = Self(<C::Scalar as PrimeField>::MULTIPLICATIVE_GENERATOR);
    const S: u32 = <C::Scalar as PrimeField>::S;
    const ROOT_OF_UNITY: Self = Self(<C::Scalar as PrimeField>::ROOT_OF_UNITY);
    const ROOT_OF_UNITY_INV: Self = Self(<C::Scalar as PrimeField>::ROOT_OF_UNITY_INV);
    const DELTA: Self = Self(<C::Scalar as PrimeField>::DELTA);

    fn from_str_vartime(s: &str) -> Option<Self> {
        <C::Scalar as PrimeField>::from_str_vartime(s).map(Self)
    }

    fn from_u128(v: u128) -> Self {
        Self(<C::Scalar as PrimeField>::from_u128(v))
    }

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        <C::Scalar as PrimeField>::from_repr(repr).map(Self)
    }

    fn from_repr_vartime(repr: Self::Repr) -> Option<Self> {
        <C::Scalar as PrimeField>::from_repr_vartime(repr).map(Self)
    }

    fn to_repr(&self) -> Self::Repr {
        PrimeField::to_repr(&self.0)
    }

    fn is_odd(&self) -> Choice {
        PrimeField::is_odd(&self.0)
    }

    fn is_even(&self) -> Choice {
        PrimeField::is_even(&self.0)
    }
}

impl<C: Backend> DefaultIsZeroes for Scalar<C> {}

impl<C: Backend> FromUintUnchecked for Scalar<C> {
    type Uint = C::Uint;

    fn from_uint_unchecked(uint: C::Uint) -> Self {
        Self(<C::Scalar as FromUintUnchecked>::from_uint_unchecked(uint))
    }
}

impl<C: Backend> Invert for Scalar<C> {
    type Output = CtOption<Self>;

    fn invert(&self) -> CtOption<Self> {
        super::invert(self)
    }

    fn invert_vartime(&self) -> CtOption<Self> {
        super::invert_vartime(self)
    }
}

impl<C: Backend> IsHigh for Scalar<C> {
    fn is_high(&self) -> Choice {
        self.0.is_high()
    }
}

impl<C: Backend> Shr<usize> for Scalar<C> {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self {
        let mut s = self;
        s >>= rhs;
        s
    }
}

impl<C: Backend> Shr<usize> for &Scalar<C> {
    type Output = Scalar<C>;

    fn shr(self, rhs: usize) -> Scalar<C> {
        *self >> rhs
    }
}

impl<C: Backend> ShrAssign<usize> for Scalar<C> {
    fn shr_assign(&mut self, rhs: usize) {
        let mut uint = C::Uint::from(&*self);
        uint >>= rhs;
        *self = Self::from_uint_unchecked(uint);
    }
}

impl<C: Backend> From<u32> for Scalar<C> {
    fn from(n: u32) -> Self {
        Self(C::Scalar::from(n))
    }
}

impl<C: Backend> From<u64> for Scalar<C> {
    fn from(n: u64) -> Self {
        Self(C::Scalar::from(n))
    }
}

impl<C: Backend> From<u128> for Scalar<C> {
    fn from(n: u128) -> Self {
        Self(C::Scalar::from(n))
    }
}

impl<C: Backend> From<Scalar<C>> for FieldBytes<C> {
    fn from(scalar: Scalar<C>) -> Self {
        scalar.0.into()
    }
}

impl<C: Backend> From<&Scalar<C>> for FieldBytes<C> {
    fn from(scalar: &Scalar<C>) -> Self {
        scalar.0.into()
    }
}

impl<C: Backend> From<ScalarValue<Accelerated<C>>> for Scalar<C> {
    fn from(w: ScalarValue<Accelerated<C>>) -> Self {
        Self::from(&w)
    }
}

impl<C: Backend> From<&ScalarValue<Accelerated<C>>> for Scalar<C> {
    fn from(w: &ScalarValue<Accelerated<C>>) -> Self {
        Self::from_uint_unchecked(*w.as_uint())
    }
}

impl<C: Backend> From<Scalar<C>> for ScalarValue<Accelerated<C>> {
    fn from(scalar: Scalar<C>) -> Self {
        Self::from(&scalar)
    }
}

impl<C: Backend> From<&Scalar<C>> for ScalarValue<Accelerated<C>> {
    fn from(scalar: &Scalar<C>) -> Self {
        ScalarValue::from_uint_unchecked(C::Uint::from(scalar))
    }
}

impl<C: Backend> From<&SecretKey<Accelerated<C>>> for Scalar<C> {
    fn from(secret_key: &SecretKey<Accelerated<C>>) -> Self {
        *secret_key.to_nonzero_scalar()
    }
}

impl<C: Backend> Add<Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn add(self, other: Scalar<C>) -> Scalar<C> {
        Scalar(self.0 + other.0)
    }
}

impl<C: Backend> Add<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn add(self, other: &Scalar<C>) -> Scalar<C> {
        Scalar(self.0 + other.0)
    }
}

impl<C: Backend> Add<&Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn add(self, other: &Scalar<C>) -> Scalar<C> {
        Scalar(self.0 + other.0)
    }
}

impl<C: Backend> AddAssign<Scalar<C>> for Scalar<C> {
    fn add_assign(&mut self, rhs: Scalar<C>) {
        self.0 += rhs.0;
    }
}

impl<C: Backend> AddAssign<&Scalar<C>> for Scalar<C> {
    fn add_assign(&mut self, rhs: &Scalar<C>) {
        self.0 += rhs.0;
    }
}

impl<C: Backend> Sub<Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn sub(self, other: Scalar<C>) -> Scalar<C> {
        Scalar(self.0 - other.0)
    }
}

impl<C: Backend> Sub<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn sub(self, other: &Scalar<C>) -> Scalar<C> {
        Scalar(self.0 - other.0)
    }
}

impl<C: Backend> Sub<&Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn sub(self, other: &Scalar<C>) -> Scalar<C> {
        Scalar(self.0 - other.0)
    }
}

impl<C: Backend> SubAssign<Scalar<C>> for Scalar<C> {
    fn sub_assign(&mut self, rhs: Scalar<C>) {
        self.0 -= rhs.0;
    }
}

impl<C: Backend> SubAssign<&Scalar<C>> for Scalar<C> {
    fn sub_assign(&mut self, rhs: &Scalar<C>) {
        self.0 -= rhs.0;
    }
}

impl<C: Backend> Mul<Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn mul(self, other: Scalar<C>) -> Scalar<C> {
        Scalar(self.0 * other.0)
    }
}

impl<C: Backend> Mul<&Scalar<C>> for &Scalar<C> {
    type Output = Scalar<C>;

    fn mul(self, other: &Scalar<C>) -> Scalar<C> {
        Scalar(self.0 * other.0)
    }
}

impl<C: Backend> Mul<&Scalar<C>> for Scalar<C> {
    type Output = Scalar<C>;

    fn mul(self, other: &Scalar<C>) -> Scalar<C> {
        Scalar(self.0 * other.0)
    }
}

impl<C: Backend> MulAssign<Scalar<C>> for Scalar<C> {
    fn mul_assign(&mut self, rhs: Scalar<C>) {
        self.0 *= rhs.0;
    }
}

impl<C: Backend> MulAssign<&Scalar<C>> for Scalar<C> {
    fn mul_assign(&mut self, rhs: &Scalar<C>) {
        self.0 *= rhs.0;
    }
}

impl<C: Backend> Neg for Scalar<C> {
    type Output = Scalar<C>;

    fn neg(self) -> Scalar<C> {
        Scalar(-self.0)
    }
}

impl<C: Backend> Neg for &Scalar<C> {
    type Output = Scalar<C>;

    fn neg(self) -> Scalar<C> {
        Scalar(-self.0)
    }
}

impl<C: Backend, T> Reduce<T> for Scalar<C>
where
    C::Scalar: Reduce<T>,
{
    fn reduce(n: &T) -> Self {
        Self(<C::Scalar as Reduce<T>>::reduce(n))
    }
}

// NOTE: routed through [`Backend::reduce_nonzero`] rather than delegated to
// the wrapped scalar: not every curve implements `ReduceNonZero` on its
// scalar (P-384's does not), and the trait's contract is a nonzero result
// (e.g. P-256's native impl is the `(w mod (n-1)) + 1` bijection, not
// `Reduce`). Curves with a native impl override the backend method to keep
// it unchanged.
impl<C: Backend> ReduceNonZero<C::Uint> for Scalar<C> {
    fn reduce_nonzero(n: &C::Uint) -> Self {
        Self(C::reduce_nonzero(n))
    }
}

impl<C: Backend> Sum for Scalar<C> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        Self(iter.map(|s| s.0).sum())
    }
}

impl<'a, C: Backend> Sum<&'a Scalar<C>> for Scalar<C> {
    fn sum<I: Iterator<Item = &'a Scalar<C>>>(iter: I) -> Self {
        Self(iter.map(|s| s.0).sum())
    }
}

impl<C: Backend> Product for Scalar<C> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        Self(iter.map(|s| s.0).product())
    }
}

impl<'a, C: Backend> Product<&'a Scalar<C>> for Scalar<C> {
    fn product<I: Iterator<Item = &'a Scalar<C>>>(iter: I) -> Self {
        Self(iter.map(|s| s.0).product())
    }
}

impl<C: Backend> ConditionallySelectable for Scalar<C> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(C::Scalar::conditional_select(&a.0, &b.0, choice))
    }
}

impl<C: Backend> ConstantTimeEq for Scalar<C> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(&self.0, &other.0)
    }
}

impl<C: Backend> CtEq for Scalar<C> {
    fn ct_eq(&self, other: &Self) -> elliptic_curve::bigint::Choice {
        CtEq::ct_eq(&self.0, &other.0)
    }
}

impl<C: Backend> CtSelect for Scalar<C> {
    fn ct_select(&self, other: &Self, choice: elliptic_curve::bigint::Choice) -> Self {
        Self(CtSelect::ct_select(&self.0, &other.0, choice))
    }
}

impl<C: Backend> Generate for Scalar<C> {
    fn try_generate_from_rng<R: TryCryptoRng + ?Sized>(rng: &mut R) -> Result<Self, R::Error> {
        Ok(Self::from_uint_unchecked(C::Uint::try_random_mod_vartime(
            rng,
            ScalarValue::<Accelerated<C>>::MODULUS.as_nz_ref(),
        )?))
    }
}

impl<C: Backend> Retrieve for Scalar<C> {
    type Output = C::Uint;

    fn retrieve(&self) -> C::Uint {
        C::Uint::from(*self)
    }
}

impl<C: Backend> From<elliptic_curve::NonZeroScalar<Accelerated<C>>> for Scalar<C> {
    fn from(nz: elliptic_curve::NonZeroScalar<Accelerated<C>>) -> Self {
        *nz.as_ref()
    }
}

impl<C: Backend> TryFrom<Scalar<C>> for elliptic_curve::NonZeroScalar<Accelerated<C>> {
    type Error = elliptic_curve::Error;

    fn try_from(scalar: Scalar<C>) -> Result<Self, Self::Error> {
        Option::from(elliptic_curve::NonZeroScalar::new(scalar)).ok_or(elliptic_curve::Error)
    }
}

macro_rules! impl_scalar_mul {
    ($ty:ty, $self_:ident, $rhs_:ident, $body:expr) => {
        impl<C: Backend> Mul<$ty> for Scalar<C> {
            type Output = ProjectivePoint<C>;
            fn mul($self_, $rhs_: $ty) -> ProjectivePoint<C> {
                $body
            }
        }
    };
}

macro_rules! impl_scalar_mulvartime {
    ($ty:ty, $self_:ident, $rhs_:ident, $body:expr) => {
        impl<C: Backend> MulVartime<$ty> for Scalar<C> {
            fn mul_vartime($self_, $rhs_: $ty) -> <Self as Mul<$ty>>::Output {
                $body
            }
        }
    };
}

impl_scalar_mul!(AffinePoint<C>, self, rhs, super::mul(&self, &rhs));
impl_scalar_mul!(&AffinePoint<C>, self, rhs, super::mul(&self, rhs));
impl_scalar_mul!(ProjectivePoint<C>, self, rhs, super::mul_projective(&self, &rhs));
impl_scalar_mul!(&ProjectivePoint<C>, self, rhs, super::mul_projective(&self, rhs));
impl_scalar_mulvartime!(AffinePoint<C>, self, rhs, super::mul(&self, &rhs));
impl_scalar_mulvartime!(&AffinePoint<C>, self, rhs, super::mul(&self, rhs));
impl_scalar_mulvartime!(ProjectivePoint<C>, self, rhs, super::mul_projective(&self, &rhs));
impl_scalar_mulvartime!(&ProjectivePoint<C>, self, rhs, super::mul_projective(&self, rhs));
