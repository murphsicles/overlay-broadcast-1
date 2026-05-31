//! Node access (REQ-BSV-080/081/082/083). All implementations treat node responses
//! as untrusted: defensive parsing, no panic on malformed input; chain-terminating
//! validation is the caller's job against the [`HeaderChain`](crate::HeaderChain)
//! trust root.
use crate::error::BsvError;
use crate::hash::{double_sha256, Hash256};
use crate::header::BlockHeader;
use crate::txid::Txid;
use std::collections::HashMap;
use thiserror::Error;

/// Errors from a node client.
#[derive(Debug, Error)]
pub enum NodeError {
    /// The requested item was not found.
    #[error("not found")]
    NotFound,
    /// The node was unreachable.
    #[error("node unreachable: {0}")]
    Unreachable(String),
    /// The node returned a malformed or unparseable response.
    #[error("bad node response")]
    BadResponse,
    /// An underlying BSV parse error.
    #[error(transparent)]
    Bsv(#[from] BsvError),
}

/// A txid's merkle branch within a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleBranch {
    /// The ordered sibling path from the leaf upward.
    pub branch: Vec<Hash256>,
    /// The leaf index within the block's transactions.
    pub index: u64,
    /// The height of the block containing the transaction.
    pub block_height: u64,
}

/// Abstract access to a BSV node.
pub trait NodeClient {
    /// Submit a raw transaction; returns its txid.
    ///
    /// # Errors
    /// [`NodeError`] on transport or response failure.
    fn submit_tx(&self, raw: &[u8]) -> Result<Txid, NodeError>;

    /// Fetch the header at a height.
    ///
    /// # Errors
    /// [`NodeError::NotFound`] / transport errors.
    fn header_by_height(&self, height: u64) -> Result<BlockHeader, NodeError>;

    /// Fetch the header with a given block hash.
    ///
    /// # Errors
    /// [`NodeError::NotFound`] / transport errors.
    fn header_by_hash(&self, hash: &Hash256) -> Result<BlockHeader, NodeError>;

    /// Fetch the merkle branch proving a txid's inclusion.
    ///
    /// # Errors
    /// [`NodeError::NotFound`] / transport errors.
    fn merkle_branch_for_txid(&self, txid: &Txid) -> Result<MerkleBranch, NodeError>;

    /// Fetch up to `count` consecutive headers from `from`.
    ///
    /// # Errors
    /// [`NodeError`] on transport or response failure.
    fn header_stream(&self, from: u64, count: u64) -> Result<Vec<BlockHeader>, NodeError>;
}

/// An offline client serving genuine committed fixtures for deterministic CI. It
/// never fabricates chain data (REQ-BSV-081).
#[derive(Debug, Default)]
pub struct OfflineNodeClient {
    by_height: HashMap<u64, BlockHeader>,
    by_hash: HashMap<Hash256, BlockHeader>,
    branches: HashMap<Txid, MerkleBranch>,
}

impl OfflineNodeClient {
    /// An empty offline client.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a genuine header at a height.
    pub fn insert_header(&mut self, height: u64, header: BlockHeader) {
        self.by_hash.insert(header.block_hash(), header);
        self.by_height.insert(height, header);
    }

    /// Record a genuine merkle branch for a txid.
    pub fn insert_branch(&mut self, txid: Txid, branch: MerkleBranch) {
        self.branches.insert(txid, branch);
    }

    /// Load the genuine BSV block-181 fixture: its header and the merkle branches of
    /// its two transactions (crates/bsv/fixtures/block_000181.json).
    ///
    /// # Errors
    /// [`BsvError`] only if the committed fixture constants are malformed (they are not).
    pub fn with_block_181() -> Result<Self, BsvError> {
        let mut client = Self::new();
        let header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::from_display_hex(
                "00000000b5ef0ea215becad97402ce59d1416fe554261405cda943afd2a8c8f2",
            )?,
            merkle_root: Hash256::from_display_hex(
                "ed92b1db0b3e998c0a4351ee3f825fd5ac6571ce50c050b4b45df015092a6c36",
            )?,
            time: 1_231_740_133,
            bits: 0x1d00_ffff,
            nonce: 792_669_465,
        };
        client.insert_header(181, header);
        let t0 = Txid::from_display_hex(
            "8347cee4a1cb5ad1bb0d92e86e6612dbf6cfc7649c9964f210d4069b426e720a",
        )?;
        let t1 = Txid::from_display_hex(
            "a16f3ce4dd5deb92d98ef5cf8afeaf0775ebca408f708b2146c4fb42b41e14be",
        )?;
        client.insert_branch(
            t0,
            MerkleBranch {
                branch: vec![*t1.as_hash()],
                index: 0,
                block_height: 181,
            },
        );
        client.insert_branch(
            t1,
            MerkleBranch {
                branch: vec![*t0.as_hash()],
                index: 1,
                block_height: 181,
            },
        );
        Ok(client)
    }
}

impl NodeClient for OfflineNodeClient {
    fn submit_tx(&self, raw: &[u8]) -> Result<Txid, NodeError> {
        Ok(Txid::from_hash(double_sha256(raw)))
    }
    fn header_by_height(&self, height: u64) -> Result<BlockHeader, NodeError> {
        self.by_height
            .get(&height)
            .copied()
            .ok_or(NodeError::NotFound)
    }
    fn header_by_hash(&self, hash: &Hash256) -> Result<BlockHeader, NodeError> {
        self.by_hash.get(hash).copied().ok_or(NodeError::NotFound)
    }
    fn merkle_branch_for_txid(&self, txid: &Txid) -> Result<MerkleBranch, NodeError> {
        self.branches.get(txid).cloned().ok_or(NodeError::NotFound)
    }
    fn header_stream(&self, from: u64, count: u64) -> Result<Vec<BlockHeader>, NodeError> {
        let mut out = Vec::new();
        let mut i = 0u64;
        while i < count {
            let height = from.checked_add(i).ok_or(NodeError::BadResponse)?;
            if let Some(header) = self.by_height.get(&height) {
                out.push(*header);
            }
            i = i.checked_add(1).ok_or(NodeError::BadResponse)?;
        }
        Ok(out)
    }
}

/// A pluggable transport for a live node (so the client logic is testable against
/// recorded responses without a network).
pub trait Transport {
    /// HTTP GET the path, returning the response body bytes.
    ///
    /// # Errors
    /// [`NodeError`] on transport failure.
    fn get(&self, path: &str) -> Result<Vec<u8>, NodeError>;

    /// HTTP POST `body` to the path, returning the response body bytes.
    ///
    /// # Errors
    /// [`NodeError`] on transport failure.
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, NodeError>;
}

/// A client against a Teranode-target node over an injected [`Transport`]
/// (REQ-BSV-082). Responses are parsed defensively (REQ-BSV-083).
#[derive(Debug)]
pub struct TeranodeClient<T: Transport> {
    transport: T,
}

impl<T: Transport> TeranodeClient<T> {
    /// Create a client over a transport.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: Transport> NodeClient for TeranodeClient<T> {
    fn submit_tx(&self, raw: &[u8]) -> Result<Txid, NodeError> {
        let body = self.transport.post("/tx", raw)?;
        let text = core::str::from_utf8(&body).map_err(|_| NodeError::BadResponse)?;
        Txid::from_display_hex(text.trim()).map_err(|_| NodeError::BadResponse)
    }
    fn header_by_height(&self, height: u64) -> Result<BlockHeader, NodeError> {
        let raw = self
            .transport
            .get(&format!("/header/height/{height}/raw"))?;
        BlockHeader::parse(&raw).map_err(|_| NodeError::BadResponse)
    }
    fn header_by_hash(&self, hash: &Hash256) -> Result<BlockHeader, NodeError> {
        let raw = self
            .transport
            .get(&format!("/header/{}/raw", hash.to_display_hex()))?;
        BlockHeader::parse(&raw).map_err(|_| NodeError::BadResponse)
    }
    fn merkle_branch_for_txid(&self, txid: &Txid) -> Result<MerkleBranch, NodeError> {
        let body = self
            .transport
            .get(&format!("/tx/{}/proof", txid.to_display_hex()))?;
        let text = core::str::from_utf8(&body).map_err(|_| NodeError::BadResponse)?;
        parse_branch(text)
    }
    fn header_stream(&self, from: u64, count: u64) -> Result<Vec<BlockHeader>, NodeError> {
        let mut out = Vec::new();
        let mut i = 0u64;
        while i < count {
            let height = from.checked_add(i).ok_or(NodeError::BadResponse)?;
            out.push(self.header_by_height(height)?);
            i = i.checked_add(1).ok_or(NodeError::BadResponse)?;
        }
        Ok(out)
    }
}

// Parse a merkle-branch response: line 1 = block height, line 2 = index, then one
// sibling display-hex per line. Defensive: any malformed field is a BadResponse.
fn parse_branch(text: &str) -> Result<MerkleBranch, NodeError> {
    let mut lines = text.lines();
    let block_height = lines
        .next()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .ok_or(NodeError::BadResponse)?;
    let index = lines
        .next()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .ok_or(NodeError::BadResponse)?;
    let mut branch = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        branch.push(Hash256::from_display_hex(trimmed).map_err(|_| NodeError::BadResponse)?);
    }
    Ok(MerkleBranch {
        branch,
        index,
        block_height,
    })
}
