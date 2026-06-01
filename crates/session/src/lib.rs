#![forbid(unsafe_code)]
//! `session`: GB 2623780 B on-chain transaction lifecycle. A session transaction
//! (GB Tables 1-2) carries a member input/output pair per eligible member (the output
//! a bare multisig spendable by member or broadcaster), a broadcaster input/output,
//! and an OP_FALSE OP_RETURN output with the rekeying metadata. Members sign
//! SIGHASH_SINGLE (their own output only); the broadcaster signs LAST under
//! SIGHASH_ALL over every output including the OP_RETURN, so members cannot see or
//! influence the rekeying keys before submission (GB §6.5). Off-chain (nominal-fee)
//! and on-block subscription, renewal, and revocation are modelled.

mod builder;
mod channel;
mod error;
mod subscription;

pub use builder::{
    build_session, ready_to_release, sign_broadcaster, sign_member, verify_broadcaster,
    verify_member, MemberSpec, SessionParams, SessionTx,
};
pub use channel::{Envelope, SecureChannel};
pub use error::SesError;
pub use subscription::{SubSession, Subscription, SubscriptionMode};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use bsv::{op, OutPoint, ScriptOp, Txid};

    fn keypair(seed: u8) -> ([u8; 32], [u8; 33]) {
        let key = ckd::XPriv::from_seed(&[seed; 32]).unwrap();
        let private: [u8; 32] = key.private_key_bytes().try_into().unwrap();
        (private, key.public_key_compressed().unwrap())
    }

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_display_hex(&format!("{n:02x}").repeat(32)).unwrap(),
            vout: 0,
        }
    }

    fn members_and_params(payload: &[u8]) -> (Vec<MemberSpec>, SessionParams, [u8; 32], [u8; 32]) {
        let (m0_priv, m0_pub) = keypair(1);
        let (_m1_priv, m1_pub) = keypair(2);
        let (b_priv, b_pub) = keypair(9);
        let members = vec![
            MemberSpec {
                member_pubkey: m0_pub,
                funding: outpoint(0),
                input_value: 10_000,
                output_value: 9_000,
            },
            MemberSpec {
                member_pubkey: m1_pub,
                funding: outpoint(1),
                input_value: 10_000,
                output_value: 9_000,
            },
        ];
        let params = SessionParams {
            broadcaster_pubkey: b_pub,
            broadcaster_funding: outpoint(9),
            broadcaster_input_value: 50_000,
            broadcaster_output_value: 40_000,
            rekeying_payload: payload.to_vec(),
        };
        (members, params, m0_priv, b_priv)
    }

    // TST-SES-001: the session transaction matches GB Tables 1-2.
    #[test]
    fn tst_ses_001_structure() {
        let (members, params, _, _) = members_and_params(b"E(k_G)");
        let session = build_session(&members, &params).unwrap();
        assert_eq!(session.transaction.inputs.len(), 3); // 2 members + broadcaster
        assert_eq!(session.transaction.outputs.len(), 4); // 2 member outputs + broadcaster + OP_RETURN
        assert_eq!(session.broadcaster_index(), 2);
        // member output is a bare multisig OP_1 <P_M> <P_B> OP_2 OP_CHECKMULTISIG.
        let ops = bsv::parse_script(&session.transaction.outputs[0].locking_script).unwrap();
        assert_eq!(ops.first(), Some(&ScriptOp::Op(op::N1)));
        assert_eq!(ops.last(), Some(&ScriptOp::Op(op::CHECKMULTISIG)));
        // the last output is the OP_RETURN data carrier.
        assert_eq!(
            bsv::parse_data_carrier(&session.transaction.outputs[3].locking_script).unwrap(),
            b"E(k_G)"
        );
    }

    // TST-SES-002/003 (§6.5): a member's SIGHASH_SINGLE signature covers only its own
    // output, so it is computed and stays valid regardless of the OP_RETURN; the
    // broadcaster's SIGHASH_ALL seals the OP_RETURN and breaks if it changes.
    #[test]
    fn tst_ses_002_003_sighash_discipline() {
        // build with an EMPTY OP_RETURN — members sign before the rekeying payload exists.
        let (members, params, m0_priv, b_priv) = members_and_params(b"");
        let (_, m0_pub) = keypair(1);
        let (_, b_pub) = keypair(9);
        let mut tx = build_session(&members, &params).unwrap().transaction;
        let bcast = 2usize;

        sign_member(&mut tx, 0, &m0_priv, &m0_pub, 10_000).unwrap();
        assert!(verify_member(&tx, 0, &m0_pub, 10_000).unwrap());

        // the broadcaster sets the real OP_RETURN and signs ALL, last.
        let op_index = tx.outputs.len() - 1;
        tx.outputs[op_index] = bsv::build_data_carrier(b"real rekeying keys");
        sign_broadcaster(&mut tx, bcast, &b_priv, &b_pub, 50_000).unwrap();
        assert!(
            verify_member(&tx, 0, &m0_pub, 10_000).unwrap(),
            "member SINGLE unaffected"
        );
        assert!(verify_broadcaster(&tx, bcast, &b_pub, 50_000).unwrap());

        // changing the OP_RETURN keeps the member SINGLE valid but breaks broadcaster ALL.
        tx.outputs[op_index] = bsv::build_data_carrier(b"tampered keys");
        assert!(verify_member(&tx, 0, &m0_pub, 10_000).unwrap());
        assert!(
            !verify_broadcaster(&tx, bcast, &b_pub, 50_000).unwrap(),
            "broadcaster seals the OP_RETURN"
        );

        // SIGHASH_SINGLE index safety (REQ-BSV-031): an out-of-range member index errors.
        assert!(sign_member(&mut tx, 99, &m0_priv, &m0_pub, 10_000).is_err());
    }

    // TST-SES-010: off-chain subscription accounting — k = x / mem_fee, renewal by
    // spend, revocation by non-spend; on-block mode; and a sub-session reference.
    #[test]
    fn tst_ses_010_subscription() {
        let mut sub = Subscription::new(SubscriptionMode::OffChain, 1_000, 100).unwrap();
        assert_eq!(sub.sessions_funded(), 10); // k = x / mem_fee
        sub.renew().unwrap();
        assert_eq!(sub.renewed_count(), 1);
        assert!(!sub.is_revoked(1), "renewed for session 1");
        assert!(
            sub.is_revoked(2),
            "session 2 elapsed without renewal -> revoked"
        );
        for _ in 1..10 {
            sub.renew().unwrap();
        }
        assert!(sub.renew().is_err(), "exhausted after k renewals");

        assert!(Subscription::new(SubscriptionMode::OnBlock, 1_000, 0).is_err());
        let on_block = Subscription::new(SubscriptionMode::OnBlock, 500, 50).unwrap();
        assert_eq!(on_block.mode(), SubscriptionMode::OnBlock);
        assert_eq!(on_block.sessions_funded(), 10);

        let sub_session = SubSession::new("deadbeef".repeat(8), 0);
        assert_eq!(sub_session.index, 0);
        assert_eq!(sub_session.parent_txid.len(), 64);
    }

    // TST-SES-011 (REQ-SES-011): on-block funded subscription — the funding must meet the
    // cost (else it funds zero sessions), and the member input/output pair is SIGHASH_SINGLE
    // signed and verifies.
    #[test]
    fn tst_ses_011_on_block_funding_and_pair_signing() {
        // funding >= cost funds sessions; funding < cost funds none (tx would be rejected)
        let funded = Subscription::new(SubscriptionMode::OnBlock, 10_000, 1_000).unwrap();
        assert_eq!(funded.sessions_funded(), 10, "funding meets cost");
        let underfunded = Subscription::new(SubscriptionMode::OnBlock, 500, 1_000).unwrap();
        assert_eq!(
            underfunded.sessions_funded(),
            0,
            "funding below cost funds no session"
        );

        // the member-and-funding pair is SIGHASH_SINGLE signed over its output and verifies
        let (members, params, m0_priv, _) = members_and_params(b"on-block");
        let mut session = build_session(&members, &params).unwrap();
        sign_member(
            &mut session.transaction,
            0,
            &m0_priv,
            &members[0].member_pubkey,
            members[0].input_value,
        )
        .unwrap();
        assert!(verify_member(
            &session.transaction,
            0,
            &members[0].member_pubkey,
            members[0].input_value
        )
        .unwrap());
    }

    // TST-SES-020 (REQ-SES-020): revocation — a member unrenewed past its funded sessions is
    // revoked (timeout), and renewal restores eligibility for the renewed session.
    #[test]
    fn tst_ses_020_revocation() {
        let mut sub = Subscription::new(SubscriptionMode::OffChain, 300, 100).unwrap();
        assert_eq!(sub.sessions_funded(), 3);
        assert!(
            sub.is_revoked(5),
            "unrenewed past funded window -> revoked (timeout)"
        );
        sub.renew().unwrap();
        sub.renew().unwrap();
        assert!(!sub.is_revoked(2), "renewed through session 2 -> eligible");
        assert!(sub.is_revoked(3), "session 3 not renewed -> revoked");
    }

    // TST-SES-030 (REQ-SES-030): sub-session split — a session over many members is split so
    // each sub-session transaction carries only its members, and only those members sign it.
    #[test]
    fn tst_ses_030_sub_session_split() {
        let (members, params, m0_priv, _) = members_and_params(b"split");
        // sub-session A carries member 0 only; sub-session B carries member 1 only.
        let sub_a = build_session(&members[0..1], &params).unwrap();
        let sub_b = build_session(&members[1..2], &params).unwrap();
        assert_eq!(sub_a.member_count, 1);
        assert_eq!(sub_b.member_count, 1);

        // only the relevant member signs its sub-session (member 0 signs A and verifies)
        let mut tx_a = sub_a.transaction.clone();
        sign_member(
            &mut tx_a,
            0,
            &m0_priv,
            &members[0].member_pubkey,
            members[0].input_value,
        )
        .unwrap();
        assert!(
            verify_member(&tx_a, 0, &members[0].member_pubkey, members[0].input_value).unwrap()
        );
        // member 0's key does not validate as member 1 on sub-session B
        assert!(!verify_member(
            &sub_b.transaction,
            0,
            &members[0].member_pubkey,
            members[0].input_value
        )
        .unwrap_or(false));
    }

    // TST-SES-040 (REQ-SES-040): the broadcaster releases only after every (sub-)session
    // transaction is uploaded; a re-encrypt changes the OP_RETURN and so the broadcaster's
    // SIGHASH_ALL signature (the re-encrypt path).
    #[test]
    fn tst_ses_040_release_gated_on_upload() {
        assert!(
            !ready_to_release(&[true, false, true]),
            "not all uploaded -> hold"
        );
        assert!(
            ready_to_release(&[true, true, true]),
            "all uploaded -> release"
        );
        assert!(!ready_to_release(&[]), "nothing to release");

        // re-encrypt: a new rekeying payload yields a different broadcaster signature
        let (members, params_a, _, b_priv) = members_and_params(b"key-A");
        let mut params_b = params_a.clone();
        params_b.rekeying_payload = b"key-B-reencrypted".to_vec();
        let mut tx_a = build_session(&members, &params_a).unwrap();
        let mut tx_b = build_session(&members, &params_b).unwrap();
        let idx = tx_a.broadcaster_index();
        sign_broadcaster(
            &mut tx_a.transaction,
            idx,
            &b_priv,
            &params_a.broadcaster_pubkey,
            params_a.broadcaster_input_value,
        )
        .unwrap();
        sign_broadcaster(
            &mut tx_b.transaction,
            idx,
            &b_priv,
            &params_b.broadcaster_pubkey,
            params_b.broadcaster_input_value,
        )
        .unwrap();
        assert_ne!(
            tx_a.transaction.inputs[idx].unlocking_script,
            tx_b.transaction.inputs[idx].unlocking_script,
            "re-encrypt produces a distinct broadcaster signature"
        );
    }

    // TST-SES-050 (REQ-SES-050): the secure channel binds a member's component to its
    // session; a component lifted to a different session/transaction binding is rejected.
    #[test]
    fn tst_ses_050_secure_channel_prevents_lift() {
        let component = b"member-signed-component";
        let session_binding = b"session-broadcaster-output-A";
        let envelope = SecureChannel::seal(component, session_binding);
        assert_eq!(
            SecureChannel::open(&envelope, session_binding).as_deref(),
            Some(component.as_slice())
        );
        // an attacker lifts the component to a different (malicious non-session) binding
        assert!(
            SecureChannel::open(&envelope, b"malicious-other-transaction").is_none(),
            "lifted component is rejected"
        );
    }
}
