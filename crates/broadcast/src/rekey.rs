//! Rekeying types for the three GB strategies (REQ-BCS-010/011/012/013, GB §4.1-4.3).
//! A rekeying replaces the keys on the path(s) affected by a join or leave (LKH); the
//! three strategies differ only in how the resulting new keys are PACKAGED into
//! communiques:
//! - user-oriented (§4.1): one communique per affected user, carrying that user's whole
//!   new keyset, encrypted under a key the user already holds (its leaf key);
//! - key-oriented (§4.2): one key per communique;
//! - group-oriented (§4.3): as many keys as possible per communique (grouped by the
//!   encrypting key), minimising the communique count.
use crate::graph::UserId;
use cipher::WrappedKey;
use keygraph::NodeId;

/// A single LKH rekey message: a node's new key, wrapped under another node's key.
#[derive(Clone, Debug)]
pub struct RekeyMessage {
    /// The node whose key was replaced.
    pub new_key_node: NodeId,
    /// The node whose key encrypts the new key.
    pub under_node: NodeId,
    /// The wrapped new key.
    pub wrapped: WrappedKey,
}

/// The result of a rekeying: the rotated nodes and the LKH rekey messages.
#[derive(Clone, Debug)]
pub struct RekeyResult {
    /// The nodes whose keys were rotated (bottom-up, leaf-parent to root).
    pub replaced: Vec<NodeId>,
    /// The key-oriented rekey messages.
    pub messages: Vec<RekeyMessage>,
}

/// The rekeying strategy (GB §4.1-4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// One communique per affected user (whole keyset).
    UserOriented,
    /// One key per communique.
    KeyOriented,
    /// As many keys as possible per communique.
    GroupOriented,
}

/// What a communique's payload is encrypted under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncryptionRef {
    /// Encrypted under a node's key.
    Node(NodeId),
    /// Encrypted under a user's leaf key.
    UserLeaf(UserId),
}

/// A rekeying communique: a set of new keys encrypted under a single key.
#[derive(Clone, Debug)]
pub struct Communique {
    /// The key the payload is encrypted under.
    pub encrypted_under: EncryptionRef,
    /// The new keys carried: (node whose key is new, the wrapped key).
    pub keys: Vec<(NodeId, WrappedKey)>,
}
