#![forbid(unsafe_code)]
//! `broadcast`: GB 2623780 B. Key-graph broadcast encryption — the root maps to the
//! message-encryption key, each leaf to a user key, and a child-node key
//! authenticated-wraps its parent-node key. The message is encrypted ONCE under the
//! message key; published encrypted data items let each eligible user decrypt up
//! their path to the message key, while a non-eligible user cannot. Part 1 here is
//! the core scheme; the three rekeying strategies and session graph update build on it.

mod error;
mod graph;
mod rekey;

pub use error::BcsError;
pub use graph::{BroadcastGraph, EncryptedDataItem, UserId};
pub use rekey::{Communique, EncryptionRef, RekeyMessage, RekeyResult, Strategy};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    // TST-BCS-001/002/003: build a graph; the message is encrypted once; the items
    // wrap each parent under its child.
    #[test]
    fn tst_bcs_001_003_build_and_items() {
        let graph = BroadcastGraph::build(&[1, 2, 3, 4]).unwrap();
        assert_eq!(graph.user_count(), 4);
        let items = graph.encrypted_data_items().unwrap();
        // a 4-leaf binary tree has 6 non-root nodes (2 inner + 4 leaves).
        assert_eq!(items.len(), 6);
        let sealed = graph.encrypt_message(b"broadcast payload").unwrap();
        // a single sealed message (encrypted once).
        let _ = sealed;
    }

    // TST-BCS-004: every eligible user decrypts the message; a non-eligible user (not
    // in the graph) and a revoked user (wrong leaf key) cannot.
    #[test]
    fn tst_bcs_004_eligible_and_non_eligible() {
        let users = [10u64, 20, 30, 40];
        let graph = BroadcastGraph::build(&users).unwrap();
        let items = graph.encrypted_data_items().unwrap();
        let message = b"only eligible users read this";
        let sealed = graph.encrypt_message(message).unwrap();

        // every eligible user reaches the message key.
        for &user in &users {
            let leaf_key = graph.user_leaf_key(user).unwrap();
            let decrypted = graph
                .user_decrypt(user, &leaf_key, &items, &sealed)
                .unwrap();
            assert_eq!(decrypted.expose(), message);
        }

        // a user not in the graph is not eligible.
        let outsider_key = graph.user_leaf_key(10).unwrap();
        assert!(graph
            .user_decrypt(999, &outsider_key, &items, &sealed)
            .is_err());

        // a user with a wrong leaf key (as if revoked / rotated) cannot decrypt.
        let wrong = secmem::SecretBytes::from_slice(&[0xAAu8; 32]);
        assert!(graph.user_decrypt(20, &wrong, &items, &sealed).is_err());
    }

    // TST-BCS-001: only a power-of-two user set is accepted by the binary builder.
    #[test]
    fn tst_bcs_001_structure() {
        assert!(BroadcastGraph::build(&[1, 2, 3]).is_err());
        assert!(BroadcastGraph::build(&[]).is_err());
        assert!(BroadcastGraph::build(&[1, 2, 3, 4, 5, 6, 7, 8]).is_ok());
    }

    // TST-BCS-013 (leave): leaving rotates the path to the root; a fresh session is
    // decryptable by remaining members and the departed member is excluded.
    #[test]
    fn tst_bcs_013_leave_rekeys() {
        let mut graph = BroadcastGraph::build(&[1, 2, 3, 4]).unwrap();
        let result = graph.leave(2).unwrap();
        // the root (message key) was rotated, so a removed member's old key is stale.
        assert!(result.replaced.contains(&graph.root()));
        let items = graph.encrypted_data_items().unwrap();
        let sealed = graph.encrypt_message(b"post-leave").unwrap();
        for user in [1u64, 3, 4] {
            let leaf_key = graph.user_leaf_key(user).unwrap();
            assert_eq!(
                graph
                    .user_decrypt(user, &leaf_key, &items, &sealed)
                    .unwrap()
                    .expose(),
                b"post-leave"
            );
        }
        assert!(
            graph.user_leaf_key(2).is_none(),
            "the departed member is gone"
        );
    }

    // TST-BCS-013 (join): joining adds a leaf, rotates the new path, and the new member
    // reads new sessions but not the pre-join message.
    #[test]
    fn tst_bcs_013_join_rekeys() {
        let mut graph = BroadcastGraph::build(&[1, 2, 3, 4]).unwrap();
        let old_items = graph.encrypted_data_items().unwrap();
        let old_sealed = graph.encrypt_message(b"pre-join").unwrap();

        let sponsor = *graph.children(graph.root()).first().unwrap();
        let (result, leaf5_key) = graph.join(5, sponsor).unwrap();
        assert!(result.replaced.contains(&graph.root()));

        let items = graph.encrypted_data_items().unwrap();
        let sealed = graph.encrypt_message(b"post-join").unwrap();
        assert_eq!(
            graph
                .user_decrypt(5, &leaf5_key, &items, &sealed)
                .unwrap()
                .expose(),
            b"post-join"
        );
        let leaf1 = graph.user_leaf_key(1).unwrap();
        assert_eq!(
            graph
                .user_decrypt(1, &leaf1, &items, &sealed)
                .unwrap()
                .expose(),
            b"post-join"
        );
        // the new member cannot read the pre-join message.
        assert!(graph
            .user_decrypt(5, &leaf5_key, &old_items, &old_sealed)
            .is_err());
    }

    // TST-BCS-010/011/012: the three rekeying strategies package the same key changes
    // with their characteristic invariants; a remaining member derives the new root
    // key from its user-oriented communique.
    #[test]
    fn tst_bcs_010_011_012_strategies() {
        use secmem::SecretBytes;
        let mut graph = BroadcastGraph::build(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        let result = graph.leave(3).unwrap();

        let key_oriented = graph.communiques(&result, Strategy::KeyOriented).unwrap();
        let group_oriented = graph.communiques(&result, Strategy::GroupOriented).unwrap();
        let user_oriented = graph.communiques(&result, Strategy::UserOriented).unwrap();

        // key-oriented (§4.2): exactly one key per communique.
        assert!(key_oriented.iter().all(|c| c.keys.len() == 1));
        assert_eq!(key_oriented.len(), result.messages.len());
        // group-oriented (§4.3): minimised communique count.
        assert!(group_oriented.len() <= key_oriented.len());
        // user-oriented (§4.1): one communique per affected user, addressed to its leaf.
        assert!(user_oriented
            .iter()
            .all(|c| matches!(c.encrypted_under, EncryptionRef::UserLeaf(_))));

        // a remaining member derives the new root (message) key from its communique.
        let comm = user_oriented
            .iter()
            .find(|c| c.encrypted_under == EncryptionRef::UserLeaf(1u64))
            .unwrap();
        let leaf1 = graph.user_leaf_key(1).unwrap();
        let new_keys = BroadcastGraph::open_user_communique(comm, &leaf1).unwrap();
        let root_key = new_keys
            .iter()
            .find(|(node, _)| *node == graph.root())
            .map(|(_, key)| SecretBytes::from_slice(key.expose()))
            .unwrap();
        let sealed = graph.encrypt_message(b"new session").unwrap();
        assert_eq!(
            graph.decrypt_with_key(&root_key, &sealed).unwrap().expose(),
            b"new session"
        );
    }
}
