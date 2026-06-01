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
mod error;
mod subscription;

pub use builder::{
    build_session, sign_broadcaster, sign_member, verify_broadcaster, verify_member, MemberSpec,
    SessionParams, SessionTx,
};
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
}
