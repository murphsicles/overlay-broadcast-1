//! Shamir secret sharing over the scalar field GF(n) of secp256k1 (REQ-CUS-005). A
//! secret scalar is the constant term of a random degree-(t-1) polynomial; each share
//! is an evaluation (x_i, y_i). Any t shares reconstruct the secret by Lagrange
//! interpolation at 0; fewer reveal nothing about it.
use crate::error::CustodyError;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, Scalar};
use secmem::{OsRandom, SecureRandom};

/// A secret share: the polynomial's value `y` at the point `x`.
#[derive(Clone, Debug)]
pub struct Share {
    /// The evaluation point (the share index as a scalar).
    pub x: Scalar,
    /// The polynomial value at `x`.
    pub y: Scalar,
}

/// A cryptographically random non-zero scalar.
///
/// # Errors
/// [`CustodyError::Random`] if entropy cannot be drawn.
pub fn random_scalar() -> Result<Scalar, CustodyError> {
    for _ in 0..16u8 {
        let mut bytes = [0u8; 32];
        OsRandom
            .fill(&mut bytes)
            .map_err(|_| CustodyError::Random)?;
        if let Some(scalar) =
            Option::<Scalar>::from(Scalar::from_repr(FieldBytes::clone_from_slice(&bytes)))
        {
            if scalar != Scalar::ZERO {
                return Ok(scalar);
            }
        }
    }
    Err(CustodyError::Random)
}

/// Split `secret` into `n` shares with reconstruction threshold `t`.
///
/// # Errors
/// [`CustodyError::BadParams`] if `t == 0` or `t > n`.
pub fn split(secret: Scalar, threshold: usize, shares: usize) -> Result<Vec<Share>, CustodyError> {
    if threshold == 0 || threshold > shares {
        return Err(CustodyError::BadParams);
    }
    let mut coeffs = vec![secret];
    for _ in 1..threshold {
        coeffs.push(random_scalar()?);
    }
    let mut out = Vec::new();
    for index in 1..=shares {
        let x = Scalar::from(u64::try_from(index).map_err(|_| CustodyError::BadParams)?);
        out.push(Share {
            x,
            y: eval(&coeffs, x),
        });
    }
    Ok(out)
}

/// Reconstruct the secret from a set of shares by Lagrange interpolation at 0.
#[must_use]
pub fn reconstruct(shares: &[Share]) -> Scalar {
    let mut secret = Scalar::ZERO;
    for (j, share_j) in shares.iter().enumerate() {
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (m, share_m) in shares.iter().enumerate() {
            if m == j {
                continue;
            }
            numerator *= share_m.x;
            denominator *= share_m.x - share_j.x;
        }
        if let Some(inverse) = Option::<Scalar>::from(denominator.invert()) {
            secret += share_j.y * numerator * inverse;
        }
    }
    secret
}

fn eval(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for coeff in coeffs.iter().rev() {
        acc = acc * x + coeff;
    }
    acc
}
