//! Validation against the published BIP32 test vector 1 (REQ-CKD-001/002/003/008):
//! deterministic derivation; hardened and non-hardened modes; private and public
//! materialisation; and public-derivation/private-derivation consistency.
//!
//! The published master triple (private key, chain code, public key) is asserted in
//! full. Derived keys are pinned by their PUBLIC key at m/0H/1 — which, since
//! public = private·G is a bijection, uniquely fixes the derived private key — so
//! the assertions are against authoritative published values the code reproduces,
//! never against the code's own output.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use bsv::{bytes_to_hex, hex_to_bytes};
use ckd::{XPriv, HARDENED};

const SEED: &str = "000102030405060708090a0b0c0d0e0f";

// Published BIP32 vector 1 master (m).
const M_PRIV: &str = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
const M_CHAIN: &str = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
const M_PUB: &str = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";

// Published BIP32 vector 1 public key at m/0H/1.
const M0H1_PUB: &str = "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c";

// TST-CKD-001: master matches the published vector in full; a two-level
// hardened-then-non-hardened derivation reproduces the published m/0H/1 public key.
#[test]
fn bip32_vector_1_derivation() {
    let seed = hex_to_bytes(SEED).unwrap();
    let master = XPriv::from_seed(&seed).unwrap();
    assert_eq!(bytes_to_hex(master.private_key_bytes()), M_PRIV);
    assert_eq!(bytes_to_hex(master.chain_code()), M_CHAIN);
    assert_eq!(
        bytes_to_hex(&master.public_key_compressed().unwrap()),
        M_PUB
    );
    assert_eq!(master.depth(), 0);

    let m0h = master.derive_child(HARDENED).unwrap(); // m/0H (hardened)
    assert_eq!(m0h.depth(), 1);
    assert_eq!(m0h.child_number(), HARDENED);

    let m0h1 = m0h.derive_child(1).unwrap(); // m/0H/1 (non-hardened)
    assert_eq!(
        bytes_to_hex(&m0h1.public_key_compressed().unwrap()),
        M0H1_PUB
    );
    assert_eq!(m0h1.depth(), 2);

    // derive_path reaches the same key.
    let via_path = master.derive_path(&[HARDENED, 1]).unwrap();
    assert_eq!(
        bytes_to_hex(&via_path.public_key_compressed().unwrap()),
        M0H1_PUB
    );
    assert_eq!(via_path.private_key_bytes(), m0h1.private_key_bytes());
}

// TST-CKD-002: derivation is deterministic across independent runs.
#[test]
fn bip32_derivation_is_deterministic() {
    let seed = hex_to_bytes(SEED).unwrap();
    let a = XPriv::from_seed(&seed)
        .unwrap()
        .derive_path(&[HARDENED, 1])
        .unwrap();
    let b = XPriv::from_seed(&seed)
        .unwrap()
        .derive_path(&[HARDENED, 1])
        .unwrap();
    assert_eq!(a.private_key_bytes(), b.private_key_bytes());
    assert_eq!(a.chain_code(), b.chain_code());
}

// TST-CKD-003: non-hardened PUBLIC derivation matches private derivation; hardened
// public derivation is refused (the central CKD boundary).
#[test]
fn bip32_public_derivation_consistency() {
    let seed = hex_to_bytes(SEED).unwrap();
    let m0h = XPriv::from_seed(&seed)
        .unwrap()
        .derive_child(HARDENED)
        .unwrap();
    let xpub = m0h.to_xpub().unwrap();

    let pub_child = xpub.derive_child(1).unwrap();
    let priv_child = m0h.derive_child(1).unwrap();
    assert_eq!(
        bytes_to_hex(&pub_child.public_key_compressed()),
        bytes_to_hex(&priv_child.public_key_compressed().unwrap())
    );
    assert_eq!(bytes_to_hex(&pub_child.public_key_compressed()), M0H1_PUB);

    assert!(xpub.derive_child(HARDENED).is_err());
}
