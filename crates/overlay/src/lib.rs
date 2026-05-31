#![forbid(unsafe_code)]
//! `overlay`: EP 4 046 048 B1. An overlay key-graph over data-storage transactions
//! with first/second/third function key sets, the three claim-5 functions, and the
//! central property — seed-isolated, position-only signalling: a second module given
//! only a node position (and the first seed) can re-derive the writing key, yet
//! cannot perform the second function (e.g. cannot de-obfuscate) because it lacks the
//! second seed. Part 1 here covers the key sets, the obfuscation function, and the
//! signalling/seed-isolation properties; transaction writing and the funding /
//! application functions build on it.

mod error;
mod graph;
mod keys;

pub use ckd::Position;
pub use error::OverlayError;
pub use graph::{OverlayGraph, OverlayNetwork};
pub use keygraph::{Bounds, NodeId};
pub use keys::{deobfuscate, obfuscate, resolve_key, signal_position, OverlayKeys};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use ckd::Seeds;

    const MASTER: &[u8] = &[0x11u8; 32];

    fn bounds() -> Bounds {
        Bounds {
            max_depth: 8,
            max_breadth: 8,
            max_nodes: 256,
        }
    }

    // TST-OVL-001/002: an overlay graph is built over data-storage-transaction nodes,
    // for Metanet and for a second generic instantiation.
    #[test]
    fn tst_ovl_001_002_graph_build() {
        let mut metanet = OverlayGraph::new(OverlayNetwork::Metanet, bounds());
        let root = metanet.root();
        let a = metanet.add_node(root, 0).unwrap();
        let a0 = metanet.add_node(a, 0).unwrap();
        assert_eq!(metanet.position_of(a0).unwrap().coords(), &[0, 0]);
        metanet.keygraph().verify_invariants().unwrap();
        assert_eq!(metanet.network(), &OverlayNetwork::Metanet);

        let mut generic =
            OverlayGraph::new(OverlayNetwork::Generic("acme-overlay".into()), bounds());
        let g0 = generic.add_node(generic.root(), 5).unwrap();
        assert_eq!(generic.position_of(g0).unwrap().coords(), &[5]);
    }

    // TST-OVL-031: the three key sets are derivable from one master seed and are
    // independent at a given position.
    #[test]
    fn tst_ovl_031_three_key_sets_independent() {
        let keys = OverlayKeys::from_master(MASTER).unwrap();
        let pos = Position::new(vec![2, 3]);
        let first = keys.writing_key(&pos).unwrap();
        let second = keys.second_key(&pos).unwrap();
        let third = keys.third_key(&pos).unwrap();
        assert_ne!(first.private_key_bytes(), second.private_key_bytes());
        assert_ne!(first.private_key_bytes(), third.private_key_bytes());
        assert_ne!(second.private_key_bytes(), third.private_key_bytes());
        // re-derivation is stable.
        let keys2 = OverlayKeys::from_master(MASTER).unwrap();
        assert_eq!(
            keys2.writing_key(&pos).unwrap().private_key_bytes(),
            first.private_key_bytes()
        );
    }

    // TST-OVL-021a: the obfuscation function round-trips; a tampered payload and a
    // wrong key are rejected.
    #[test]
    fn tst_ovl_021a_obfuscation() {
        let keys = OverlayKeys::from_master(MASTER).unwrap();
        let pos = Position::new(vec![1]);
        let second = keys.second_key(&pos).unwrap();
        let payload = b"node payload content";
        let obf = obfuscate(&second, payload).unwrap();
        assert_eq!(deobfuscate(&second, &obf).unwrap().expose(), payload);
        // tamper fails.
        let mut bad = obf.clone();
        if let Some(b) = bad.bytes.first_mut() {
            *b ^= 0xff;
        }
        assert!(deobfuscate(&second, &bad).is_err());
        // the wrong second key (a different position) fails.
        let other = keys.second_key(&Position::new(vec![2])).unwrap();
        assert!(deobfuscate(&other, &obf).is_err());
    }

    // TST-OVL-050/061: signalling transmits only a position; the receiver re-derives
    // the writing key from first seed + position, and the second-function key from
    // second seed + position.
    #[test]
    fn tst_ovl_050_061_position_signalling() {
        let seeds = Seeds::from_master(MASTER).unwrap();
        let keys = OverlayKeys::from_seeds(Seeds::from_master(MASTER).unwrap());
        let pos = Position::new(vec![4, 2]);
        let signalled = signal_position(&pos);
        assert_eq!(signalled, vec![4, 2]); // only the position travels

        let writing = resolve_key(&signalled, seeds.first().expose()).unwrap();
        assert_eq!(
            writing.private_key_bytes(),
            keys.writing_key(&pos).unwrap().private_key_bytes()
        );
        let second = resolve_key(&signalled, seeds.second().expose()).unwrap();
        assert_eq!(
            second.private_key_bytes(),
            keys.second_key(&pos).unwrap().private_key_bytes()
        );
    }

    // TST-OVL-051/052: a module holding only the first seed + a position can re-derive
    // the writing key but CANNOT de-obfuscate (it lacks the second seed); the writing
    // and second keys are independent, so leaking the writing key grants no
    // de-obfuscation ability.
    #[test]
    fn tst_ovl_051_052_seed_isolation_negative() {
        let seeds = Seeds::from_master(MASTER).unwrap();
        let keys = OverlayKeys::from_seeds(Seeds::from_master(MASTER).unwrap());
        let pos = Position::new(vec![7]);
        let signalled = signal_position(&pos);

        // the true obfuscation uses the SECOND key set.
        let second = keys.second_key(&pos).unwrap();
        let obf = obfuscate(&second, b"only the second seed can read this").unwrap();

        // B has only the FIRST seed: it can re-derive the writing key...
        let b_writing = resolve_key(&signalled, seeds.first().expose()).unwrap();
        assert_eq!(
            b_writing.private_key_bytes(),
            keys.writing_key(&pos).unwrap().private_key_bytes()
        );
        // ...but the best key B can form (from the first seed) does NOT de-obfuscate.
        assert!(
            deobfuscate(&b_writing, &obf).is_err(),
            "first-seed holder cannot de-obfuscate"
        );

        // writing and second keys at the position are independent.
        assert_ne!(b_writing.private_key_bytes(), second.private_key_bytes());
    }
}
