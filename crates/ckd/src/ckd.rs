//! BIP32-style hierarchical child key derivation over secp256k1 (REQ-CKD-001..008,
//! EP cl.1,2,6,7). The 64-byte HMAC-SHA512 output splits into a 32-byte scalar
//! addend (left) and a 32-byte child chain code (right); child private = (parent +
//! left) mod n; child public = parent public + left·G; index is big-endian u32; the
//! hardened bit is index >= 2^31. Seeds and chain codes are held as `SecretBytes`.
use crate::error::CkdError;
use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey};
use secmem::SecretBytes;
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// The first hardened index (2^31): indices at or above this are hardened.
pub const HARDENED: u32 = 0x8000_0000;

/// An extended PRIVATE key: a private key plus its chain code, depth, and child
/// number. The secrets are zeroizing and redacted in `Debug`.
#[derive(Debug)]
pub struct XPriv {
    private_key: SecretBytes,
    chain_code: SecretBytes,
    depth: u8,
    child_number: u32,
}

/// An extended PUBLIC key: a compressed public key plus its chain code, depth, and
/// child number. Supports non-hardened public derivation only.
#[derive(Debug)]
pub struct XPub {
    public_key: [u8; 33],
    chain_code: SecretBytes,
    depth: u8,
    child_number: u32,
}

impl XPriv {
    /// The master extended key from a seed (HMAC-SHA512 with key "Bitcoin seed").
    ///
    /// # Errors
    /// [`CkdError::BadKey`] for a seed of invalid length or a degenerate master key.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CkdError> {
        if seed.len() < 16 || seed.len() > 64 {
            return Err(CkdError::BadKey);
        }
        let i = hmac_sha512(b"Bitcoin seed", seed)?;
        let (il, ir) = i.split_at(32);
        let scalar = scalar_from_canonical(il).ok_or(CkdError::BadKey)?;
        if is_zero(&scalar) {
            return Err(CkdError::BadKey);
        }
        Ok(Self {
            private_key: SecretBytes::from_slice(il),
            chain_code: SecretBytes::from_slice(ir),
            depth: 0,
            child_number: 0,
        })
    }

    /// Derive a child extended private key at `index` (hardened iff index >= 2^31).
    ///
    /// # Errors
    /// [`CkdError`] on a degenerate derivation (negligible) or an invalid parent.
    pub fn derive_child(&self, index: u32) -> Result<Self, CkdError> {
        let mut data = Vec::with_capacity(37);
        if index >= HARDENED {
            data.push(0x00);
            data.extend_from_slice(self.private_key.expose());
        } else {
            data.extend_from_slice(&self.public_key_compressed()?);
        }
        data.extend_from_slice(&index.to_be_bytes());
        let i = hmac_sha512(self.chain_code.expose(), &data)?;
        let (il, ir) = i.split_at(32);
        let left = scalar_from_canonical(il).ok_or(CkdError::DerivationFailed)?;
        let parent = scalar_from_canonical(self.private_key.expose()).ok_or(CkdError::BadKey)?;
        let child = left + parent;
        if is_zero(&child) {
            return Err(CkdError::DerivationFailed);
        }
        let child_bytes = child.to_repr();
        let depth = self.depth.checked_add(1).ok_or(CkdError::InvalidIndex)?;
        Ok(Self {
            private_key: SecretBytes::from_slice(child_bytes.as_slice()),
            chain_code: SecretBytes::from_slice(ir),
            depth,
            child_number: index,
        })
    }

    /// Derive along a path of child indices.
    ///
    /// # Errors
    /// Propagates [`XPriv::derive_child`] errors.
    pub fn derive_path(&self, path: &[u32]) -> Result<Self, CkdError> {
        let mut current = self.dup();
        for &index in path {
            current = current.derive_child(index)?;
        }
        Ok(current)
    }

    /// The compressed public key for this extended key.
    ///
    /// # Errors
    /// [`CkdError::BadKey`] if the private key is invalid.
    pub fn public_key_compressed(&self) -> Result<[u8; 33], CkdError> {
        let secret =
            SecretKey::from_slice(self.private_key.expose()).map_err(|_| CkdError::BadKey)?;
        encode_point(&secret.public_key().to_projective())
    }

    /// The neutered extended PUBLIC key.
    ///
    /// # Errors
    /// [`CkdError::BadKey`] if the private key is invalid.
    pub fn to_xpub(&self) -> Result<XPub, CkdError> {
        Ok(XPub {
            public_key: self.public_key_compressed()?,
            chain_code: SecretBytes::from_slice(self.chain_code.expose()),
            depth: self.depth,
            child_number: self.child_number,
        })
    }

    /// The 32 raw private-key bytes (an auditable point of exposure).
    #[must_use]
    pub fn private_key_bytes(&self) -> &[u8] {
        self.private_key.expose()
    }

    /// The 32-byte chain code.
    #[must_use]
    pub fn chain_code(&self) -> &[u8] {
        self.chain_code.expose()
    }

    /// The derivation depth.
    #[must_use]
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// The child number this key was derived at (0 for the master).
    #[must_use]
    pub fn child_number(&self) -> u32 {
        self.child_number
    }

    fn dup(&self) -> Self {
        Self {
            private_key: SecretBytes::from_slice(self.private_key.expose()),
            chain_code: SecretBytes::from_slice(self.chain_code.expose()),
            depth: self.depth,
            child_number: self.child_number,
        }
    }
}

impl XPub {
    /// Derive a child extended PUBLIC key (non-hardened only).
    ///
    /// # Errors
    /// [`CkdError::HardenedNeedsPrivate`] for a hardened index; [`CkdError`] on a
    /// degenerate derivation or an invalid parent public key.
    pub fn derive_child(&self, index: u32) -> Result<Self, CkdError> {
        if index >= HARDENED {
            return Err(CkdError::HardenedNeedsPrivate);
        }
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(&index.to_be_bytes());
        let i = hmac_sha512(self.chain_code.expose(), &data)?;
        let (il, ir) = i.split_at(32);
        let left = scalar_from_canonical(il).ok_or(CkdError::DerivationFailed)?;
        let parent = PublicKey::from_sec1_bytes(&self.public_key)
            .map_err(|_| CkdError::BadPublicKey)?
            .to_projective();
        let child = (ProjectivePoint::GENERATOR * left) + parent;
        let depth = self.depth.checked_add(1).ok_or(CkdError::InvalidIndex)?;
        Ok(Self {
            public_key: encode_point(&child)?,
            chain_code: SecretBytes::from_slice(ir),
            depth,
            child_number: index,
        })
    }

    /// The compressed public key.
    #[must_use]
    pub fn public_key_compressed(&self) -> [u8; 33] {
        self.public_key
    }

    /// The 32-byte chain code.
    #[must_use]
    pub fn chain_code(&self) -> &[u8] {
        self.chain_code.expose()
    }

    /// The child number this key was derived at.
    #[must_use]
    pub fn child_number(&self) -> u32 {
        self.child_number
    }
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64], CkdError> {
    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| CkdError::DerivationFailed)?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(bytes.as_slice());
    Ok(out)
}

fn scalar_from_canonical(bytes: &[u8]) -> Option<Scalar> {
    if bytes.len() != 32 {
        return None;
    }
    let fb = FieldBytes::clone_from_slice(bytes);
    Option::from(Scalar::from_repr(fb))
}

fn is_zero(scalar: &Scalar) -> bool {
    scalar.to_repr().iter().all(|b| *b == 0)
}

fn encode_point(point: &ProjectivePoint) -> Result<[u8; 33], CkdError> {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true);
    encoded
        .as_bytes()
        .try_into()
        .map_err(|_| CkdError::DerivationFailed)
}
