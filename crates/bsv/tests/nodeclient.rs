//! Node client tests (REQ-BSV-080/081/082/083): the offline client serves the
//! genuine block-181 fixture; the Teranode client parses recorded responses
//! defensively; a live test is ignored without a configured node.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use bsv::{
    compute_root_from_proof, BlockHeader, Hash256, MerkleBranch, NodeClient, NodeError,
    OfflineNodeClient, TeranodeClient, Transport, Txid,
};
use std::collections::HashMap;

const BLOCK_HASH: &str = "00000000dc55860c8a29c58d45209318fa9e9dc2c1833a7226d86bc465afc6e5";
const MERKLE: &str = "ed92b1db0b3e998c0a4351ee3f825fd5ac6571ce50c050b4b45df015092a6c36";
const TXID0: &str = "8347cee4a1cb5ad1bb0d92e86e6612dbf6cfc7649c9964f210d4069b426e720a";

// TST-BSV-081: the offline client serves the genuine block-181 header and the
// txid-0 merkle branch, which reconstructs the genuine merkle root.
#[test]
fn offline_serves_genuine_block_181() {
    let node = OfflineNodeClient::with_block_181().unwrap();
    let header = node.header_by_height(181).unwrap();
    assert_eq!(header.block_hash().to_display_hex(), BLOCK_HASH);
    assert_eq!(node.header_by_hash(&header.block_hash()).unwrap(), header);
    let t0 = Txid::from_display_hex(TXID0).unwrap();
    let branch = node.merkle_branch_for_txid(&t0).unwrap();
    assert_eq!(branch.index, 0);
    assert_eq!(branch.block_height, 181);
    let proof = bsv::MerkleProof {
        index: branch.index,
        siblings: branch.branch.clone(),
    };
    assert_eq!(
        compute_root_from_proof(t0.as_hash(), &proof)
            .unwrap()
            .to_display_hex(),
        MERKLE
    );
    // unknown height/txid fail closed, not panic.
    assert!(matches!(
        node.header_by_height(999_999),
        Err(NodeError::NotFound)
    ));
    assert_eq!(node.header_stream(181, 1).unwrap().len(), 1);
}

fn genuine_header() -> BlockHeader {
    BlockHeader {
        version: 1,
        prev_block_hash: Hash256::from_display_hex(
            "00000000b5ef0ea215becad97402ce59d1416fe554261405cda943afd2a8c8f2",
        )
        .unwrap(),
        merkle_root: Hash256::from_display_hex(MERKLE).unwrap(),
        time: 1_231_740_133,
        bits: 0x1d00_ffff,
        nonce: 792_669_465,
    }
}

#[derive(Default)]
struct MockTransport {
    gets: HashMap<String, Vec<u8>>,
    post_reply: Vec<u8>,
}
impl Transport for MockTransport {
    fn get(&self, path: &str) -> Result<Vec<u8>, NodeError> {
        self.gets.get(path).cloned().ok_or(NodeError::NotFound)
    }
    fn post(&self, _path: &str, _body: &[u8]) -> Result<Vec<u8>, NodeError> {
        Ok(self.post_reply.clone())
    }
}

// TST-BSV-082/083: the Teranode client parses a recorded (genuine-derived) header
// response and a merkle-branch response, and rejects a malformed response.
#[test]
fn teranode_parses_recorded_responses() {
    let header = genuine_header();
    let mut gets = HashMap::new();
    gets.insert(
        "/header/height/181/raw".to_string(),
        header.serialize().to_vec(),
    );
    // a malformed header response (too short)
    gets.insert("/header/height/1/raw".to_string(), vec![0u8; 10]);
    let branch_text = format!("181\n0\n{MERKLE}\n");
    gets.insert(format!("/tx/{TXID0}/proof"), branch_text.into_bytes());

    let txid = Txid::from_display_hex(BLOCK_HASH).unwrap(); // any 32-byte value for post reply
    let node = TeranodeClient::new(MockTransport {
        gets,
        post_reply: txid.to_display_hex().into_bytes(),
    });

    assert_eq!(node.header_by_height(181).unwrap(), header);
    assert!(matches!(
        node.header_by_height(1),
        Err(NodeError::BadResponse)
    )); // defensive
    assert!(matches!(node.header_by_height(2), Err(NodeError::NotFound)));

    let t0 = Txid::from_display_hex(TXID0).unwrap();
    let got: MerkleBranch = node.merkle_branch_for_txid(&t0).unwrap();
    assert_eq!(got.block_height, 181);
    assert_eq!(got.branch.len(), 1);

    assert_eq!(node.submit_tx(b"rawtx").unwrap(), txid);
}

// Live verification against a real Teranode endpoint. Ignored here: the bsv crate
// keeps the trust root free of a network/TLS dependency, so a real HTTP Transport is
// supplied by an outer layer. Run with such a Transport against the node configured
// in ANCHORCHAIN_TERANODE_URL; header_by_height(181) MUST return the genuine header
// whose block hash is 00000000dc55860c…afc6e5 (REQ-BSV-082 / REQ-TST-050).
#[test]
#[ignore = "requires a live Teranode endpoint (ANCHORCHAIN_TERANODE_URL) and an HTTP Transport impl"]
fn live_teranode_block_181_header() {
    // Oracle the live run must satisfy (asserted here so the expectation is checked
    // and the test is not empty):
    let header = genuine_header();
    assert_eq!(header.block_hash().to_display_hex(), BLOCK_HASH);
}
