//! The first/second/third function key sets, the obfuscation function (claim 5a),
//! and seed-isolated position-only signalling (REQ-OVL-010/020/021a/030/031/050/061).
use crate::error::OverlayError;
use cipher::{open, seal, Ciphertext, NONCE_LEN};
use ckd::{Position, Seeds, XPriv};
use hkdf::Hkdf;
use secmem::{OsRandom, SecretBytes, SecureRandom};
use sha2::Sha256;
use zeroize::Zeroize;

const OBFUSCATION_INFO: &[u8] = b"overlay/obfuscation-key/v1";
const OBFUSCATION_AAD: &[u8] = b"overlay/obfuscation/v1";

/// The three function key sets, each derived from its own seed with the same graph
/// structure (EP cl.1,6; REQ-OVL-010/020/030/031).
#[derive(Debug)]
pub struct OverlayKeys {
    seeds: Seeds,
}

impl OverlayKeys {
    /// Derive all three key sets from a single master seed (EP cl.7).
    ///
    /// # Errors
    /// [`OverlayError::Ckd`] on a derivation failure.
    pub fn from_master(master_seed: &[u8]) -> Result<Self, OverlayError> {
        Ok(Self {
            seeds: Seeds::from_master(master_seed)?,
        })
    }

    /// Construct from explicit (independently-imported) seeds.
    #[must_use]
    pub fn from_seeds(seeds: Seeds) -> Self {
        Self { seeds }
    }

    /// The first (writing) key at a position (hardened; signs child-tx inputs).
    ///
    /// # Errors
    /// [`OverlayError::Ckd`].
    pub fn writing_key(&self, position: &Position) -> Result<XPriv, OverlayError> {
        Ok(self.seeds.writing_key(position)?)
    }

    /// The second-function key at a position (e.g. the obfuscation key set).
    ///
    /// # Errors
    /// [`OverlayError::Ckd`].
    pub fn second_key(&self, position: &Position) -> Result<XPriv, OverlayError> {
        Ok(self.seeds.second_function_key(position)?)
    }

    /// The third-function key at a position.
    ///
    /// # Errors
    /// [`OverlayError::Ckd`].
    pub fn third_key(&self, position: &Position) -> Result<XPriv, OverlayError> {
        Ok(self.seeds.third_function_key(position)?)
    }
}

/// Derive the symmetric obfuscation key from a node's second-function key
/// (domain-separated HKDF-SHA256; REQ-CKD-008, REQ-OVL-021a).
fn obfuscation_key(second_key: &XPriv) -> Result<SecretBytes, OverlayError> {
    let hk = Hkdf::<Sha256>::new(None, second_key.private_key_bytes());
    let mut okm = [0u8; 32];
    hk.expand(OBFUSCATION_INFO, &mut okm)
        .map_err(|_| OverlayError::Random)?;
    let key = SecretBytes::from_slice(&okm);
    okm.zeroize();
    Ok(key)
}

/// Obfuscate a node payload under the second-function key (AES-256-GCM, claim 5a).
/// The strength is exactly that of AES-256-GCM under the derived key — no more
/// (REQ-OVL-022).
///
/// # Errors
/// [`OverlayError`] on a randomness or cipher failure.
pub fn obfuscate(second_key: &XPriv, payload: &[u8]) -> Result<Ciphertext, OverlayError> {
    let key = obfuscation_key(second_key)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRandom
        .fill(&mut nonce)
        .map_err(|_| OverlayError::Random)?;
    let bytes = seal(key.expose(), &nonce, payload, OBFUSCATION_AAD)?;
    Ok(Ciphertext { nonce, bytes })
}

/// De-obfuscate a node payload; requires the (correct) second-function key.
///
/// # Errors
/// [`OverlayError::Cipher`] if the key is wrong or the payload was tampered.
pub fn deobfuscate(
    second_key: &XPriv,
    ciphertext: &Ciphertext,
) -> Result<SecretBytes, OverlayError> {
    let key = obfuscation_key(second_key)?;
    Ok(open(
        key.expose(),
        &ciphertext.nonce,
        &ciphertext.bytes,
        OBFUSCATION_AAD,
    )?)
}

/// Transmit ONLY a node position from a first to a second software module
/// (EP cl.3,16; REQ-OVL-050). The result carries no key material.
#[must_use]
pub fn signal_position(position: &Position) -> Vec<u32> {
    position.coords().to_vec()
}

/// The receiver-side method (EP cl.16; REQ-OVL-050/061): given a signalled position
/// and a seed (and CKD), determine the key for the node at that position. With the
/// FIRST seed this yields the writing key; with the SECOND seed, the obfuscation key
/// set; etc. — the key is re-derivable from position + seed alone.
///
/// # Errors
/// [`OverlayError::Ckd`].
pub fn resolve_key(signalled_coords: &[u32], seed: &[u8]) -> Result<XPriv, OverlayError> {
    let position = Position::new(signalled_coords.to_vec());
    Ok(XPriv::from_seed(seed)?.derive_path(&position.hardened_path())?)
}
