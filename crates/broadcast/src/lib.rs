#![forbid(unsafe_code)]
//! `broadcast`: GB 2623780 B. Key-graph broadcast encryption — the root maps to the
//! message-encryption key, each leaf to a user key, and a child-node key
//! authenticated-wraps its parent-node key. The message is encrypted ONCE under the
//! message key; published encrypted data items let each eligible user decrypt up
//! their path to the message key, while a non-eligible user cannot. Part 1 here is
//! the core scheme; the three rekeying strategies and session graph update build on it.

mod error;
mod graph;

pub use error::BcsError;
pub use graph::{BroadcastGraph, EncryptedDataItem, UserId};

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
}
