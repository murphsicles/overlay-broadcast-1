//! Genuine-data verification against BSV mainnet block 181 (REQ-BSV-081). Values are
//! the genuine fixture at crates/bsv/fixtures/block_000181.json.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use bsv::{
    compute_root_from_proof, merkle_root, verify_against_chain, BlockHeader, BsvError, Hash256,
    HeaderChain, MerkleProof, Txid,
};

const HEIGHT: u64 = 181;
const BLOCK_HASH: &str = "00000000dc55860c8a29c58d45209318fa9e9dc2c1833a7226d86bc465afc6e5";
const PREV: &str = "00000000b5ef0ea215becad97402ce59d1416fe554261405cda943afd2a8c8f2";
const MERKLE: &str = "ed92b1db0b3e998c0a4351ee3f825fd5ac6571ce50c050b4b45df015092a6c36";
const TXID0: &str = "8347cee4a1cb5ad1bb0d92e86e6612dbf6cfc7649c9964f210d4069b426e720a";
const TXID1: &str = "a16f3ce4dd5deb92d98ef5cf8afeaf0775ebca408f708b2146c4fb42b41e14be";

fn genuine_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block_hash: Hash256::from_display_hex(PREV).unwrap(),
        merkle_root: Hash256::from_display_hex(MERKLE).unwrap(),
        time: 1_231_740_133,
        bits: 0x1d00_ffff,
        nonce: 792_669_465,
    }
}

// TST-BSV-040: the genuine header hashes to the genuine block hash.
#[test]
fn genuine_block_hash() {
    assert_eq!(genuine_header().block_hash().to_display_hex(), BLOCK_HASH);
}

// TST-BSV-041: the genuine proof-of-work meets the encoded target; a tampered nonce
// does not, and the chain rejects it.
#[test]
fn genuine_pow_and_bad_pow() {
    assert!(genuine_header().meets_target());
    let mut weak = genuine_header();
    weak.nonce = 0;
    assert!(!weak.meets_target());
    let mut chain = HeaderChain::new(HEIGHT);
    assert_eq!(chain.add(weak).unwrap_err(), BsvError::ChainBadPow);
}

// TST-BSV-013: the genuine transaction ids hash to the genuine merkle root.
#[test]
fn genuine_merkle_root() {
    let leaves = [
        *Txid::from_display_hex(TXID0).unwrap().as_hash(),
        *Txid::from_display_hex(TXID1).unwrap().as_hash(),
    ];
    assert_eq!(merkle_root(&leaves).unwrap().to_display_hex(), MERKLE);
}

// TST-BSV-041/042/043: header chain accepts the genuine header; an inclusion proof
// verifies against the chain root; wrong height and non-linking headers are rejected.
#[test]
fn genuine_chain_and_inclusion_proof() {
    let mut chain = HeaderChain::new(HEIGHT);
    chain.add(genuine_header()).unwrap();
    assert_eq!(chain.tip_height(), Some(HEIGHT));
    assert_eq!(
        chain
            .merkle_root_at_height(HEIGHT)
            .unwrap()
            .to_display_hex(),
        MERKLE
    );

    let t0 = *Txid::from_display_hex(TXID0).unwrap().as_hash();
    let t1 = *Txid::from_display_hex(TXID1).unwrap().as_hash();
    let proof = MerkleProof {
        index: 0,
        siblings: vec![t1],
    };
    assert_eq!(
        compute_root_from_proof(&t0, &proof)
            .unwrap()
            .to_display_hex(),
        MERKLE
    );
    verify_against_chain(&t0, &proof, HEIGHT, &chain).unwrap();
    assert!(verify_against_chain(&t0, &proof, HEIGHT + 1, &chain).is_err());

    // a header that does not link to the tip is rejected at the linkage check.
    let mut next = genuine_header();
    next.prev_block_hash = Hash256::from_display_hex(MERKLE).unwrap();
    assert_eq!(chain.add(next).unwrap_err(), BsvError::ChainNotLinked);
}
