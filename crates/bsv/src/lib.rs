#![forbid(unsafe_code)]
//! `bsv`: BSV primitives and the validated block-header chain — the single root of
//! trust for the whole system (REQ-BSV-042). Post-Genesis protocol only; secp256k1;
//! on-chain value is named exclusively in minor units.
//!
//! This module group provides hashing and byte-order discipline, transaction ids,
//! block headers and the [`HeaderChain`], and merkle inclusion-proof verification
//! that terminates in the header chain. Transaction/script/sighash, the data
//! carrier, and the node client are layered on in the same crate.

mod error;
mod hash;
mod header;
mod headerchain;
mod merkle;
mod txid;

pub use error::BsvError;
pub use hash::{bytes_to_hex, double_sha256, hash160, hex_to_bytes, sha256, Hash256};
pub use header::{BlockHeader, HEADER_LEN};
pub use headerchain::HeaderChain;
pub use merkle::{
    compute_root_from_proof, hash_pair, merkle_root, verify_against_chain, MerkleProof,
};
pub use txid::Txid;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    // TST-BSV-002: known-answer vectors for the hash primitives.
    #[test]
    fn tst_bsv_002_hash_kats() {
        // double-SHA-256 of the empty string (widely published vector).
        assert_eq!(
            bytes_to_hex(double_sha256(b"").internal()),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
        // SHA-256("abc") (FIPS-180 vector).
        assert_eq!(
            bytes_to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // hash160 of a published compressed public key (Bitcoin wiki vector).
        let pk = hex_to_bytes("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352")
            .unwrap();
        assert_eq!(
            bytes_to_hex(&hash160(&pk)),
            "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
        );
    }

    // TST-BSV-001: internal/display byte order round-trips through the single
    // conversion point.
    #[test]
    fn tst_bsv_001_byte_order_roundtrip() {
        let display = "00000000dc55860c8a29c58d45209318fa9e9dc2c1833a7226d86bc465afc6e5";
        let h = Hash256::from_display_hex(display).unwrap();
        assert_eq!(h.to_display_hex(), display);
        // internal order is the reverse of display order.
        let internal_hex = bytes_to_hex(h.internal());
        assert_eq!(internal_hex.len(), 64);
        assert_ne!(internal_hex, display);
    }

    // TST-BSV-043: merkle root / proof over a two-leaf tree, with tamper rejection.
    #[test]
    fn tst_bsv_043_merkle_two_leaf() {
        let a = double_sha256(b"leaf-a");
        let b = double_sha256(b"leaf-b");
        let root = merkle_root(&[a, b]).unwrap();
        assert_eq!(root, hash_pair(&a, &b));
        let proof = MerkleProof {
            index: 0,
            siblings: vec![b],
        };
        assert_eq!(compute_root_from_proof(&a, &proof).unwrap(), root);
        // a wrong sibling fails.
        let bad = MerkleProof {
            index: 0,
            siblings: vec![a],
        };
        assert_ne!(compute_root_from_proof(&a, &bad).unwrap(), root);
        // odd self-pairing: three leaves duplicate the last.
        let c = double_sha256(b"leaf-c");
        let r3 = merkle_root(&[a, b, c]).unwrap();
        assert_eq!(r3, hash_pair(&hash_pair(&a, &b), &hash_pair(&c, &c)));
    }

    // TST-BSV-040: header serialise/parse round-trip is byte-identical.
    #[test]
    fn tst_bsv_040_header_roundtrip() {
        let header = BlockHeader {
            version: 1,
            prev_block_hash: double_sha256(b"prev"),
            merkle_root: double_sha256(b"root"),
            time: 1_231_740_133,
            bits: 0x1d00_ffff,
            nonce: 42,
        };
        let raw = header.serialize();
        assert_eq!(raw.len(), HEADER_LEN);
        assert_eq!(BlockHeader::parse(&raw).unwrap(), header);
        assert_eq!(
            BlockHeader::parse(&raw[..79]).unwrap_err(),
            BsvError::Length {
                expected: 80,
                got: 79
            }
        );
    }
}
