//! The broadcast key graph (REQ-BCS-001..004): a key graph whose root maps to the
//! message-encryption key and whose leaves map to per-user keys. A child-node key
//! encrypts (authenticated-wraps) its parent-node key; the published encrypted data
//! items let each eligible user decrypt up their path to the message key, while a
//! non-eligible user (not in the graph, or holding a wrong/revoked key) cannot.
use crate::error::BcsError;
use crate::rekey::{Communique, EncryptionRef, RekeyMessage, RekeyResult, Strategy};
use cipher::{open_for, seal_for, unwrap, wrap, Recipient, SealedMessage, WrappedKey};
use keygraph::{Bounds, KeyGraph, NodeId};
use secmem::{OsRandom, SecretBytes};
use std::collections::{HashMap, HashSet};

const MESSAGE_AAD: &[u8] = b"broadcast/message/v1";
const KEY_LEN: usize = 32;

/// A user identifier.
pub type UserId = u64;

/// An encrypted data item: a parent-node key wrapped under a child-node key (GB cl.1).
#[derive(Clone, Debug)]
pub struct EncryptedDataItem {
    /// The child node whose key wraps the parent key.
    pub node: NodeId,
    /// The parent node whose key is wrapped.
    pub parent: NodeId,
    /// The authenticated wrap of the parent key.
    pub wrapped_parent_key: WrappedKey,
}

/// A broadcast key graph with a symmetric key per node.
#[derive(Debug)]
pub struct BroadcastGraph {
    graph: KeyGraph,
    keys: HashMap<NodeId, SecretBytes>,
    user_leaves: HashMap<UserId, NodeId>,
}

impl BroadcastGraph {
    /// Build a balanced binary broadcast graph over a power-of-two set of users,
    /// assigning a fresh random key to every node (REQ-BCS-001).
    ///
    /// # Errors
    /// [`BcsError::BadStructure`] if the user count is not a power of two.
    pub fn build(user_ids: &[UserId]) -> Result<Self, BcsError> {
        let n = user_ids.len();
        if n == 0 || !n.is_power_of_two() {
            return Err(BcsError::BadStructure);
        }
        // breadth/node headroom above the binary shape so a join can add a leaf.
        let max_nodes = n.checked_mul(4).ok_or(BcsError::BadStructure)?;
        let mut graph = KeyGraph::with_root(Bounds {
            max_depth: 64,
            max_breadth: 8,
            max_nodes,
        });
        let leaves = build_binary(&mut graph, n)?;
        let mut keys = HashMap::new();
        for layer in graph.layers() {
            for node in layer {
                let _ = keys.insert(node, random_key()?);
            }
        }
        let mut user_leaves = HashMap::new();
        for (index, user) in user_ids.iter().enumerate() {
            let leaf = leaves.get(index).copied().ok_or(BcsError::BadStructure)?;
            let _ = user_leaves.insert(*user, leaf);
        }
        Ok(Self {
            graph,
            keys,
            user_leaves,
        })
    }

    /// The number of users.
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.user_leaves.len()
    }

    /// The message-encryption (root) key.
    fn message_key(&self) -> Result<&SecretBytes, BcsError> {
        self.keys
            .get(&self.graph.root())
            .ok_or(BcsError::MissingKey)
    }

    /// A copy of a user's leaf key (distributed to the user out of band).
    #[must_use]
    pub fn user_leaf_key(&self, user: UserId) -> Option<SecretBytes> {
        let leaf = self.user_leaves.get(&user)?;
        self.keys
            .get(leaf)
            .map(|key| SecretBytes::from_slice(key.expose()))
    }

    /// Generate the encrypted data items: each non-root node's key wraps its parent's
    /// key (REQ-BCS-003, GB cl.1).
    ///
    /// # Errors
    /// [`BcsError`] on a missing key or wrap failure.
    pub fn encrypted_data_items(&self) -> Result<Vec<EncryptedDataItem>, BcsError> {
        let mut items = Vec::new();
        for (&node, node_key) in &self.keys {
            if let Some(parent) = self.graph.parent(node) {
                let parent_key = self.keys.get(&parent).ok_or(BcsError::MissingKey)?;
                let wrapped_parent_key = wrap(node_key.expose(), parent_key.expose())?;
                items.push(EncryptedDataItem {
                    node,
                    parent,
                    wrapped_parent_key,
                });
            }
        }
        Ok(items)
    }

    /// Encrypt the message ONCE under the message key (REQ-BCS-002). Symmetric here;
    /// the cipher selector supports asymmetric per REQ-CIPH-014.
    ///
    /// # Errors
    /// [`BcsError`] on a missing key or cipher failure.
    pub fn encrypt_message(&self, plaintext: &[u8]) -> Result<SealedMessage, BcsError> {
        let key = self.message_key()?;
        Ok(seal_for(
            Recipient::Symmetric(key.expose()),
            plaintext,
            MESSAGE_AAD,
        )?)
    }

    /// Decrypt the message as `user`, using the user's leaf key and the published
    /// items. An eligible user reaches the message key; a non-eligible user fails
    /// (REQ-BCS-004).
    ///
    /// # Errors
    /// [`BcsError::NotEligible`] / [`BcsError::Cipher`] if the user cannot decrypt.
    pub fn user_decrypt(
        &self,
        user: UserId,
        leaf_key: &SecretBytes,
        items: &[EncryptedDataItem],
        sealed: &SealedMessage,
    ) -> Result<SecretBytes, BcsError> {
        let leaf = *self.user_leaves.get(&user).ok_or(BcsError::NotEligible)?;
        let path = self.graph.leaf_to_root(leaf)?;
        let mut current = SecretBytes::from_slice(leaf_key.expose());
        for window in path.windows(2) {
            let child = *window.first().ok_or(BcsError::NotEligible)?;
            let parent = *window.get(1).ok_or(BcsError::NotEligible)?;
            let item = items
                .iter()
                .find(|it| it.node == child && it.parent == parent)
                .ok_or(BcsError::NotEligible)?;
            current = unwrap(current.expose(), &item.wrapped_parent_key)
                .map_err(|_| BcsError::NotEligible)?;
        }
        Ok(open_for(Some(current.expose()), None, sealed, MESSAGE_AAD)?)
    }
}

impl BroadcastGraph {
    /// The root node id.
    #[must_use]
    pub fn root(&self) -> NodeId {
        self.graph.root()
    }

    /// Decrypt a sealed message directly with a (root/message) key.
    ///
    /// # Errors
    /// [`BcsError::Cipher`] if the key does not open the message.
    pub fn decrypt_with_key(
        &self,
        key: &SecretBytes,
        sealed: &SealedMessage,
    ) -> Result<SecretBytes, BcsError> {
        Ok(open_for(Some(key.expose()), None, sealed, MESSAGE_AAD)?)
    }

    /// Remove a user and rotate every key on its path to the root (those keys were
    /// known to the leaving member), returning the rekeying (REQ-BCS-013 leave).
    ///
    /// # Errors
    /// [`BcsError`] if the user is unknown or a graph/cipher operation fails.
    pub fn leave(&mut self, user: UserId) -> Result<RekeyResult, BcsError> {
        let leaf = *self.user_leaves.get(&user).ok_or(BcsError::NotEligible)?;
        let ancestors = self.ancestors_of(leaf)?;
        self.graph.remove_subtree(leaf)?;
        let _ = self.user_leaves.remove(&user);
        let _ = self.keys.remove(&leaf);
        self.rotate_and_rekey(&ancestors)
    }

    /// Add a user as a new leaf under `sponsor` and rotate the new path's keys (so the
    /// new member gets fresh keys and cannot read past messages); returns the rekeying
    /// and the new member's leaf key (REQ-BCS-013 join).
    ///
    /// # Errors
    /// [`BcsError`] if a graph/cipher operation fails.
    pub fn join(
        &mut self,
        user: UserId,
        sponsor: NodeId,
    ) -> Result<(RekeyResult, SecretBytes), BcsError> {
        let coord =
            u32::try_from(self.children_of(sponsor).len()).map_err(|_| BcsError::BadStructure)?;
        let leaf = self.graph.add_child(sponsor, coord)?;
        let leaf_key = random_key()?;
        let returned = SecretBytes::from_slice(leaf_key.expose());
        let _ = self.keys.insert(leaf, leaf_key);
        let _ = self.user_leaves.insert(user, leaf);
        let ancestors = self.ancestors_of(leaf)?;
        let result = self.rotate_and_rekey(&ancestors)?;
        Ok((result, returned))
    }

    /// Package a rekeying into communiques per the chosen strategy (GB §4.1-4.3).
    ///
    /// # Errors
    /// [`BcsError`] on a missing key or wrap failure.
    pub fn communiques(
        &self,
        result: &RekeyResult,
        strategy: Strategy,
    ) -> Result<Vec<Communique>, BcsError> {
        match strategy {
            Strategy::KeyOriented => Ok(self.communiques_key_oriented(result)),
            Strategy::GroupOriented => Ok(self.communiques_group_oriented(result)),
            Strategy::UserOriented => self.communiques_user_oriented(result),
        }
    }

    /// Open a user-oriented communique with a leaf key, yielding the new node keys.
    ///
    /// # Errors
    /// [`BcsError::Cipher`] if the leaf key does not unwrap the communique.
    pub fn open_user_communique(
        communique: &Communique,
        leaf_key: &SecretBytes,
    ) -> Result<Vec<(NodeId, SecretBytes)>, BcsError> {
        let mut out = Vec::new();
        for (node, wrapped) in &communique.keys {
            out.push((*node, unwrap(leaf_key.expose(), wrapped)?));
        }
        Ok(out)
    }

    fn ancestors_of(&self, leaf: NodeId) -> Result<Vec<NodeId>, BcsError> {
        let path = self.graph.leaf_to_root(leaf)?;
        Ok(path.get(1..).map(<[NodeId]>::to_vec).unwrap_or_default())
    }

    /// The children of a node.
    #[must_use]
    pub fn children(&self, node: NodeId) -> Vec<NodeId> {
        self.children_of(node)
    }

    fn children_of(&self, parent: NodeId) -> Vec<NodeId> {
        self.keys
            .keys()
            .copied()
            .filter(|&n| self.graph.parent(n) == Some(parent))
            .collect()
    }

    fn rotate_and_rekey(&mut self, ancestors: &[NodeId]) -> Result<RekeyResult, BcsError> {
        let mut messages = Vec::new();
        for &node in ancestors {
            let new_key = random_key()?;
            for child in self.children_of(node) {
                let under = self.keys.get(&child).ok_or(BcsError::MissingKey)?;
                let wrapped = wrap(under.expose(), new_key.expose())?;
                messages.push(RekeyMessage {
                    new_key_node: node,
                    under_node: child,
                    wrapped,
                });
            }
            let _ = self.keys.insert(node, new_key);
        }
        Ok(RekeyResult {
            replaced: ancestors.to_vec(),
            messages,
        })
    }

    fn communiques_key_oriented(&self, result: &RekeyResult) -> Vec<Communique> {
        result
            .messages
            .iter()
            .map(|m| Communique {
                encrypted_under: EncryptionRef::Node(m.under_node),
                keys: vec![(m.new_key_node, m.wrapped.clone())],
            })
            .collect()
    }

    fn communiques_group_oriented(&self, result: &RekeyResult) -> Vec<Communique> {
        let mut grouped: HashMap<NodeId, Vec<(NodeId, WrappedKey)>> = HashMap::new();
        for m in &result.messages {
            grouped
                .entry(m.under_node)
                .or_default()
                .push((m.new_key_node, m.wrapped.clone()));
        }
        grouped
            .into_iter()
            .map(|(under, keys)| Communique {
                encrypted_under: EncryptionRef::Node(under),
                keys,
            })
            .collect()
    }

    fn communiques_user_oriented(&self, result: &RekeyResult) -> Result<Vec<Communique>, BcsError> {
        let replaced: HashSet<NodeId> = result.replaced.iter().copied().collect();
        let mut communiques = Vec::new();
        for (&user, &leaf) in &self.user_leaves {
            let path = self.graph.leaf_to_root(leaf)?;
            let leaf_key = self.keys.get(&leaf).ok_or(BcsError::MissingKey)?;
            let mut keys = Vec::new();
            for node in path {
                if replaced.contains(&node) {
                    let new_key = self.keys.get(&node).ok_or(BcsError::MissingKey)?;
                    keys.push((node, wrap(leaf_key.expose(), new_key.expose())?));
                }
            }
            if !keys.is_empty() {
                communiques.push(Communique {
                    encrypted_under: EncryptionRef::UserLeaf(user),
                    keys,
                });
            }
        }
        Ok(communiques)
    }
}

fn build_binary(graph: &mut KeyGraph, n_users: usize) -> Result<Vec<NodeId>, BcsError> {
    let depth = n_users.trailing_zeros();
    let mut current = vec![graph.root()];
    for _ in 0..depth {
        let mut next = Vec::new();
        for node in current {
            for coord in 0u32..2 {
                next.push(graph.add_child(node, coord)?);
            }
        }
        current = next;
    }
    Ok(current)
}

fn random_key() -> Result<SecretBytes, BcsError> {
    SecretBytes::random(&mut OsRandom, KEY_LEN).map_err(|_| BcsError::Random)
}
