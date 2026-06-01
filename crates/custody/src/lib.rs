//! Custody (Section 11): threshold signing and key lifecycle.
//!
//! - [`threshold`] — FROST-style threshold Schnorr where the private key is never
//!   reconstructed (REQ-CUS-001/003). FROST is a published, peer-reviewed *Schnorr*
//!   construction, so its combined signature is Schnorr, not ECDSA.
//! - [`shamir`] — Shamir secret sharing over the secp256k1 scalar field (REQ-CUS-005).
//! - [`reconstruction`] — fallback that transiently reconstructs the key to produce a
//!   consensus-valid low-S ECDSA signature, then wipes it (REQ-CUS-005).
//! - [`lifecycle`] — anchorable, hash-chained rotation/revocation log (REQ-CUS-006).
//!
//! Conformance boundary (see `docs/ARCHITECTURE.md`): REQ-CUS-004 calls for a TRUE
//! THRESHOLD *ECDSA* signature — `partial_sign` + `combine` yielding a standard low-S
//! BSV ECDSA signature under the group key with NO reconstruction. FROST yields
//! Schnorr; a standard-ECDSA threshold combine needs a pinned, audited secp256k1
//! threshold-ECDSA (GG18/GG20-style) crate, which is not present in this environment
//! and must not be hand-rolled (Paillier/MtA is too dangerous to ship unreviewed). The
//! `#[ignore]`d `tst_cus_004_threshold_ecdsa` marks that gap explicitly; the
//! reconstruction mode covers the on-chain ECDSA path in the meantime.
#![forbid(unsafe_code)]

pub mod error;
pub mod lifecycle;
pub mod reconstruction;
pub mod shamir;
pub mod threshold;

pub use error::CustodyError;
pub use lifecycle::{verify_lifecycle, EventKind, KeyCustodian, LifecycleEvent};
pub use shamir::{random_scalar, reconstruct, split, Share};
pub use threshold::{
    aggregate, aggregated_nonce, keygen, verify, verify_commitments, GroupKey, NonceCommitment,
    NonceReveal, PartialSig, ThresholdParty, ThresholdSignature,
};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use k256::Scalar;

    // Run the full FROST round protocol for a chosen set of share indices over an
    // already-generated group, returning the combined signature. The private key is
    // never assembled — only per-share partials are combined.
    fn frost_sign(
        group: &GroupKey,
        shares: &[Share],
        signer_indices: &[usize],
        message: &[u8],
    ) -> ThresholdSignature {
        let mut parties: Vec<ThresholdParty> = signer_indices
            .iter()
            .map(|&i| ThresholdParty::new(shares[i].clone()))
            .collect();
        let signing_set: Vec<Scalar> = parties.iter().map(ThresholdParty::index).collect();
        let commitments: Vec<NonceCommitment> =
            parties.iter_mut().map(|p| p.commit().unwrap()).collect();
        let reveals: Vec<NonceReveal> = parties.iter().map(|p| p.reveal().unwrap()).collect();
        assert!(
            verify_commitments(&commitments, &reveals),
            "every nonce matches its commitment"
        );
        let aggregated_r = aggregated_nonce(&reveals);
        let partials: Vec<PartialSig> = parties
            .iter()
            .map(|p| {
                p.partial_sign(message, group, aggregated_r, &signing_set)
                    .unwrap()
            })
            .collect();
        aggregate(&reveals, &partials)
    }

    // TST-CUS-001 (REQ-CUS-001): a t-of-n threshold signature verifies against the group
    // key, combining k partial signatures. The key is never reconstructed: GroupKey only
    // exposes the public key, ThresholdParty holds a single share, and there is no API
    // that returns the whole private key.
    #[test]
    fn tst_cus_001_threshold_sign_and_verify() {
        let message = b"anchor this overlay state";
        let (group, shares) = keygen(3, 5).unwrap();
        let signature = frost_sign(&group, &shares, &[0, 2, 4], message);
        assert!(
            verify(&group, message, &signature),
            "threshold signature is valid"
        );
        assert!(
            !verify(&group, b"different message", &signature),
            "signature does not verify for another message"
        );
    }

    // TST-CUS-001 (REQ-CUS-001 / REQ-CUS-003): a sub-threshold signing set (k-1) cannot
    // produce a verifying signature — Lagrange interpolation over fewer than t shares does
    // not recover the group key, so no single share (nor any k-1 subset) can sign.
    #[test]
    fn tst_cus_001b_subthreshold_cannot_sign() {
        let message = b"k-1 must fail";
        let (group, shares) = keygen(3, 5).unwrap();
        let undersigned = frost_sign(&group, &shares, &[0, 1], message);
        assert!(
            !verify(&group, message, &undersigned),
            "k-1 shares do not yield a valid signature"
        );
    }

    // TST-CUS-003 (REQ-CUS-003): any quorum of exactly t shares from the same group
    // signs successfully — the group key is fixed, the signing subset is interchangeable.
    #[test]
    fn tst_cus_003_any_quorum_signs() {
        let message = b"second quorum";
        let (group, shares) = keygen(3, 5).unwrap();
        let signature = frost_sign(&group, &shares, &[1, 2, 3], message);
        assert!(verify(&group, message, &signature));
    }

    // TST-CUS-001 (round-one binding): a tampered nonce commitment is rejected, so a party
    // cannot adaptively choose its nonce after seeing others (rogue-nonce defence).
    #[test]
    fn tst_cus_001c_commitment_binding() {
        let (_group, shares) = keygen(2, 3).unwrap();
        let mut a = ThresholdParty::new(shares[0].clone());
        let mut b = ThresholdParty::new(shares[1].clone());
        let mut commitments = vec![a.commit().unwrap(), b.commit().unwrap()];
        let reveals = vec![a.reveal().unwrap(), b.reveal().unwrap()];
        commitments[0].commitment[0] ^= 0xFF;
        assert!(
            !verify_commitments(&commitments, &reveals),
            "a corrupted commitment fails to verify"
        );
    }

    // TST-CUS-004 (REQ-CUS-004): GAP — a TRUE THRESHOLD *ECDSA* signature (partial_sign +
    // combine yielding a standard low-S BSV ECDSA signature under the group key, with NO
    // reconstruction, k signs / k-1 fails). The pinned scheme is FROST, which yields
    // Schnorr (REQ-CUS-001/002/003); a standard-ECDSA threshold combine requires a pinned,
    // audited secp256k1 threshold-ECDSA (GG18/GG20-style) crate that is NOT in this
    // environment and must not be hand-rolled (Paillier/MtA). Reconstruction mode
    // (REQ-CUS-005, tst_cus_005_reconstruction_ecdsa) provides the ECDSA path meanwhile.
    #[test]
    #[ignore = "REQ-CUS-004 needs a pinned, audited secp256k1 threshold-ECDSA (GG20-style) crate; FROST yields Schnorr. Decision pending from the maintainer (see ARCHITECTURE.md threshold fork)."]
    fn tst_cus_004_threshold_ecdsa() {
        panic!("REQ-CUS-004 requires a pinned, audited secp256k1 threshold-ECDSA (GG20-style) crate, not present in this environment");
    }

    // TST-CUS-005 (REQ-CUS-005): reconstruction-mode produces a consensus-valid low-S ECDSA
    // signature over a prehash, verifiable against the group public key; the recovered key
    // is wiped. This is the SEPARATE fallback; default authority signing is threshold mode.
    #[test]
    fn tst_cus_005_reconstruction_ecdsa() {
        let (group, shares) = keygen(3, 5).unwrap();
        let quorum = vec![shares[0].clone(), shares[1].clone(), shares[4].clone()];
        let prehash = [0x11u8; 32];
        let signature = reconstruction::sign_prehash(&quorum, 3, &prehash).unwrap();
        let recovered_pubkey = reconstruction::public_key(&quorum, 3).unwrap();
        assert_eq!(
            recovered_pubkey,
            group.public_compressed(),
            "reconstructed key matches the threshold group key"
        );
        assert!(
            ckd::verify_der_prehash(&recovered_pubkey, &prehash, &signature),
            "ECDSA signature verifies as a standard BSV signature"
        );
    }

    // TST-CUS-005 (REQ-CUS-005, primitive): Shamir split/reconstruct round-trips at exactly
    // the threshold and any threshold subset; a sub-threshold set does not recover the secret.
    #[test]
    fn tst_cus_005b_shamir_roundtrip() {
        let secret = random_scalar().unwrap();
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(
            reconstruct(&shares[0..3]),
            secret,
            "exactly threshold shares reconstruct"
        );
        assert_eq!(
            reconstruct(&[shares[1].clone(), shares[3].clone(), shares[4].clone()]),
            secret,
            "any threshold subset reconstructs"
        );
        assert_ne!(
            reconstruct(&shares[0..2]),
            secret,
            "fewer than threshold shares do not reconstruct"
        );
    }

    // TST-CUS-005 (REQ-CUS-005, negative): reconstruction signing refuses a sub-threshold set.
    #[test]
    fn tst_cus_005c_reconstruction_requires_threshold() {
        let (_group, shares) = keygen(3, 5).unwrap();
        let prehash = [0x22u8; 32];
        assert_eq!(
            reconstruction::sign_prehash(&shares[0..2], 3, &prehash),
            Err(CustodyError::InsufficientShares)
        );
    }

    // TST-CUS-006 (REQ-CUS-006): a genesis→rotation→revocation chain verifies, the head hash
    // (anchorable on chain) changes at each step, the old key cannot sign after rotation
    // (rotation moves current_key and a revoked chain refuses rotation), and tampering with
    // any recorded event is detected.
    #[test]
    fn tst_cus_006_lifecycle_chain() {
        let key_a = [0xA1u8; 33];
        let key_b = [0xB2u8; 33];
        let mut custodian = KeyCustodian::new(key_a, 100);
        let genesis_head = custodian.head_hash();
        custodian.rotate(key_b, 200).unwrap();
        let rotated_head = custodian.head_hash();
        assert_ne!(
            genesis_head.internal(),
            rotated_head.internal(),
            "rotation changes the anchorable head"
        );
        assert_eq!(custodian.current_key(), key_b);
        custodian.revoke(300).unwrap();
        assert!(custodian.is_revoked());
        assert!(
            verify_lifecycle(custodian.events()),
            "the honest chain verifies"
        );
        assert_eq!(custodian.rotate(key_a, 400), Err(CustodyError::Revoked));
        let mut tampered = custodian.events().to_vec();
        tampered[1].public_key[0] ^= 0xFF;
        assert!(!verify_lifecycle(&tampered), "a tampered event is detected");
    }

    // TST-CUS-006 (REQ-CUS-006, terminality): a revocation must be terminal — no event may
    // follow it in a valid log, even one with a structurally correct hash.
    #[test]
    fn tst_cus_006b_revocation_is_terminal() {
        let key = [0x07u8; 33];
        let mut custodian = KeyCustodian::new(key, 1);
        custodian.revoke(2).unwrap();
        let mut events = custodian.events().to_vec();
        let prev_hash = events[1].hash;
        let forged_hash = {
            let mut buf = Vec::new();
            buf.push(1u8); // Rotation tag
            buf.extend_from_slice(&key);
            buf.extend_from_slice(&3u64.to_be_bytes());
            buf.extend_from_slice(prev_hash.internal());
            bsv::double_sha256(&buf)
        };
        events.push(LifecycleEvent {
            kind: EventKind::Rotation,
            public_key: key,
            logical_time: 3,
            prev_hash,
            hash: forged_hash,
        });
        assert!(
            !verify_lifecycle(&events),
            "no event may follow a revocation"
        );
    }

    // TST-CUS-007 (REQ-CUS-007): GAP — threshold shares must be sourced/held by the
    // KeyStore (Section 12, the `kst` crate) and computed where the share lives, not held
    // in process memory beyond use. The KeyStore is built in a later step; this test is
    // enabled once `kst` exists.
    #[test]
    #[ignore = "REQ-CUS-007 requires the KeyStore (Section 12, kst crate), built in a later step"]
    fn tst_cus_007_shares_via_keystore() {
        panic!("REQ-CUS-007 blocked on the Section 12 KeyStore (kst crate)");
    }

    // TST-CUS-010 (REQ-CUS-010 / REQ-UNI-007): the signature produced through custody is a
    // standard, low-S BSV ECDSA signature — verifiable and already S-normalized.
    #[test]
    fn tst_cus_010_signature_is_low_s() {
        use k256::ecdsa::Signature;
        let (_group, shares) = keygen(3, 5).unwrap();
        let quorum = vec![shares[0].clone(), shares[2].clone(), shares[3].clone()];
        let prehash = [0x33u8; 32];
        let der = reconstruction::sign_prehash(&quorum, 3, &prehash).unwrap();
        let signature = Signature::from_der(&der).unwrap();
        assert!(
            signature.normalize_s().is_none(),
            "the combined custody signature is already low-S"
        );
    }
}
