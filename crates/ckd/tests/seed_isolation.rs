//! Seed isolation, position mapping, and the EP-critical key-leakage negative test
//! (REQ-CKD-004/005/006/007). The leakage test demonstrates WHY non-hardened
//! derivation is hazardous (a leaked child private key plus the parent public key
//! and chain code recovers the parent private key) and PROVES that hardened
//! derivation — used for the writing key set — defeats that recovery.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use bsv::hex_to_bytes;
use ckd::{Position, Seeds, XPriv, HARDENED};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, Scalar};
use sha2::Sha512;

const MASTER: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn scalar(bytes: &[u8]) -> Scalar {
    Option::from(Scalar::from_repr(FieldBytes::clone_from_slice(bytes))).unwrap()
}

// The IL an attacker can compute from PUBLIC information only (the non-hardened
// derivation input): HMAC-SHA512(chain_code, parent_pubkey || index)[0..32].
fn il_from_public(chain_code: &[u8], parent_pub: &[u8; 33], index: u32) -> Scalar {
    let mut mac = Hmac::<Sha512>::new_from_slice(chain_code).unwrap();
    mac.update(parent_pub);
    mac.update(&index.to_be_bytes());
    let out = mac.finalize().into_bytes();
    scalar(&out[0..32])
}

// TST-CKD-006: the three seeds are distinct and domain-separated; re-derivation is
// stable; independently-imported seeds reproduce the same key sets.
#[test]
fn seeds_are_domain_separated_and_stable() {
    let master = hex_to_bytes(MASTER).unwrap();
    let seeds = Seeds::from_master(&master).unwrap();
    assert!(!seeds.first().ct_eq(seeds.second()));
    assert!(!seeds.first().ct_eq(seeds.third()));
    assert!(!seeds.second().ct_eq(seeds.third()));
    // stable across calls
    let again = Seeds::from_master(&master).unwrap();
    assert!(seeds.first().ct_eq(again.first()));
}

// TST-CKD-005: the same position under different seeds yields independent keys with
// no derivable relation.
#[test]
fn same_position_different_seeds_are_independent() {
    let master = hex_to_bytes(MASTER).unwrap();
    let seeds = Seeds::from_master(&master).unwrap();
    let pos = Position::new(vec![3, 7]);
    let k1 = seeds.writing_key(&pos).unwrap();
    let k2 = seeds.second_function_key(&pos).unwrap();
    let k3 = seeds.third_function_key(&pos).unwrap();
    assert_ne!(k1.private_key_bytes(), k2.private_key_bytes());
    assert_ne!(k1.private_key_bytes(), k3.private_key_bytes());
    assert_ne!(k2.private_key_bytes(), k3.private_key_bytes());
}

// TST-CKD-007: a position maps deterministically to a path; the key is re-derivable
// from seed + position alone.
#[test]
fn position_maps_to_reproducible_key() {
    let master = hex_to_bytes(MASTER).unwrap();
    let seeds = Seeds::from_master(&master).unwrap();
    let pos = Position::new(vec![1, 2, 3]);
    let a = seeds.writing_key(&pos).unwrap();
    let b = seeds.writing_key(&Position::new(vec![1, 2, 3])).unwrap();
    assert_eq!(a.private_key_bytes(), b.private_key_bytes());
    // a different position yields a different key.
    let c = seeds.writing_key(&Position::new(vec![1, 2, 4])).unwrap();
    assert_ne!(a.private_key_bytes(), c.private_key_bytes());
    // the position maps to a hardened path.
    assert!(pos.hardened_path().iter().all(|i| *i >= HARDENED));
}

// TST-CKD-004 (the EP-critical negative test): non-hardened leakage recovers the
// parent; hardened leakage does not.
#[test]
fn seed_isolation_under_key_leakage() {
    let seed = hex_to_bytes("000102030405060708090a0b0c0d0e0f").unwrap();
    let parent = XPriv::from_seed(&seed).unwrap();
    let parent_pub = parent.public_key_compressed().unwrap();
    let parent_priv = scalar(parent.private_key_bytes());

    // NON-HARDENED: leaking the child private key plus the parent PUBLIC key and
    // chain code recovers the parent private key. This is the hazard.
    let child_nh = parent.derive_child(7).unwrap();
    let il = il_from_public(parent.chain_code(), &parent_pub, 7);
    let recovered = scalar(child_nh.private_key_bytes()) - il;
    assert_eq!(
        recovered, parent_priv,
        "non-hardened: the parent IS recoverable"
    );

    // HARDENED (the writing key set): the same public-only attack does NOT recover
    // the parent — IL depends on the secret parent key, unavailable to the attacker.
    let child_h = parent.derive_child(HARDENED | 7).unwrap();
    let il_attack = il_from_public(parent.chain_code(), &parent_pub, HARDENED | 7);
    let attempt = scalar(child_h.private_key_bytes()) - il_attack;
    assert_ne!(
        attempt, parent_priv,
        "hardened: the parent is NOT recoverable"
    );

    // A hardened sibling is likewise unrelated to the leaked hardened child.
    let sibling_h = parent.derive_child(HARDENED | 8).unwrap();
    assert_ne!(sibling_h.private_key_bytes(), child_h.private_key_bytes());
}
