//! Reconstruction-mode signing (REQ-CUS-004): the fallback used when an ECDSA
//! signature is required on a BSV transaction (BSV consensus verifies ECDSA, not
//! Schnorr). The threshold of shares is combined transiently to recover the private
//! key, a standard low-S / RFC-6979 ECDSA signature is produced via the `ckd` signer,
//! and the recovered key material is wiped before returning. This is strictly weaker
//! than threshold mode (the key briefly exists in one place); callers prefer
//! [`crate::threshold`] wherever a Schnorr signature is acceptable.
use crate::error::CustodyError;
use crate::shamir::{reconstruct, Share};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::ProjectivePoint;
use zeroize::Zeroize;

/// The compressed public key for a set of shares (the group key), without signing.
///
/// # Errors
/// [`CustodyError::InsufficientShares`] if fewer than `threshold` shares are supplied.
pub fn public_key(shares: &[Share], threshold: usize) -> Result<[u8; 33], CustodyError> {
    if shares.len() < threshold {
        return Err(CustodyError::InsufficientShares);
    }
    let mut secret = reconstruct(shares);
    let point = ProjectivePoint::GENERATOR * secret;
    secret.zeroize();
    let encoded = point.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(CustodyError::BadShare);
    }
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Sign a 32-byte prehash with the reconstructed key, returning a DER ECDSA signature.
/// The recovered private key is zeroized before this function returns.
///
/// # Errors
/// [`CustodyError::InsufficientShares`] if too few shares; [`CustodyError::Signing`]
/// if the signature cannot be produced.
pub fn sign_prehash(
    shares: &[Share],
    threshold: usize,
    prehash: &[u8],
) -> Result<Vec<u8>, CustodyError> {
    if shares.len() < threshold {
        return Err(CustodyError::InsufficientShares);
    }
    let mut secret = reconstruct(shares);
    let mut repr = secret.to_repr();
    secret.zeroize();
    let mut private_key = [0u8; 32];
    private_key.copy_from_slice(repr.as_slice());
    for byte in repr.as_mut_slice() {
        *byte = 0;
    }
    let signature = ckd::sign_prehash_der(&private_key, prehash);
    private_key.zeroize();
    signature.map_err(|_| CustodyError::Signing)
}
