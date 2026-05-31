//! Merkle root and inclusion-proof verification with BSV odd-node self-pairing
//! (REQ-BSV-043). Verification terminates in the [`HeaderChain`] trust root.
use crate::error::BsvError;
use crate::hash::{double_sha256, Hash256};
use crate::headerchain::HeaderChain;

/// Maximum tree height accepted (a bounded-iteration guard, REQ-GOV-013): 2^64 leaves.
const MAX_TREE_HEIGHT: usize = 64;

/// Hash two ordered children into their parent node (internal byte order).
#[must_use]
pub fn hash_pair(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut buf = [0u8; 64];
    write_half(&mut buf, 0, left.internal());
    write_half(&mut buf, 32, right.internal());
    double_sha256(&buf)
}

/// Compute the merkle root of `leaves`, duplicating the last node at an odd level.
///
/// # Errors
/// [`BsvError::MerkleMismatch`] if empty; [`BsvError::OutOfRange`] if too tall.
pub fn merkle_root(leaves: &[Hash256]) -> Result<Hash256, BsvError> {
    if leaves.is_empty() {
        return Err(BsvError::MerkleMismatch);
    }
    let mut level: Vec<Hash256> = leaves.to_vec();
    let mut height = 0usize;
    while level.len() > 1 {
        height = height.checked_add(1).ok_or(BsvError::OutOfRange)?;
        if height > MAX_TREE_HEIGHT {
            return Err(BsvError::OutOfRange);
        }
        level = next_level(&level);
    }
    level.into_iter().next().ok_or(BsvError::MerkleMismatch)
}

/// An inclusion proof: a leaf index and the ordered sibling path to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    /// Zero-based index of the leaf among the block's transactions.
    pub index: u64,
    /// Sibling hashes from the leaf level upward.
    pub siblings: Vec<Hash256>,
}

/// Recompute the root implied by a leaf and its proof.
///
/// # Errors
/// [`BsvError::OutOfRange`] if the proof is implausibly long.
pub fn compute_root_from_proof(leaf: &Hash256, proof: &MerkleProof) -> Result<Hash256, BsvError> {
    if proof.siblings.len() > MAX_TREE_HEIGHT {
        return Err(BsvError::OutOfRange);
    }
    let mut current = *leaf;
    let mut index = proof.index;
    for sibling in &proof.siblings {
        current = if (index & 1) == 0 {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
        index >>= 1;
    }
    Ok(current)
}

/// Verify a leaf's inclusion against the merkle root committed by the header at
/// `height` in a validated [`HeaderChain`] (REQ-BSV-042/043).
///
/// # Errors
/// [`BsvError::MerkleMismatch`] if the height is absent or the root does not match.
pub fn verify_against_chain(
    leaf: &Hash256,
    proof: &MerkleProof,
    height: u64,
    chain: &HeaderChain,
) -> Result<(), BsvError> {
    let anchored = chain
        .merkle_root_at_height(height)
        .ok_or(BsvError::MerkleMismatch)?;
    let computed = compute_root_from_proof(leaf, proof)?;
    if computed == anchored {
        Ok(())
    } else {
        Err(BsvError::MerkleMismatch)
    }
}

fn next_level(level: &[Hash256]) -> Vec<Hash256> {
    let mut out = Vec::with_capacity(level.len().div_ceil(2));
    for pair in level.chunks(2) {
        let left = pair.first();
        let right = pair.get(1).or(left);
        if let (Some(l), Some(r)) = (left, right) {
            out.push(hash_pair(l, r));
        }
    }
    out
}

fn write_half(buf: &mut [u8; 64], off: usize, src: &[u8; 32]) {
    if let Some(end) = off.checked_add(32) {
        if let Some(dst) = buf.get_mut(off..end) {
            dst.copy_from_slice(src);
        }
    }
}
