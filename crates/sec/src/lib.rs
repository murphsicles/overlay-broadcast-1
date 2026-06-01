//! Adversarial threat model (Section 16, REQ-SEC). The full threat model is documented in
//! `docs/SECURITY.md`; this crate is the executable half — one test per threat that mounts
//! the attack and asserts the mitigation defeats it. The crate has no library code; it is
//! exercised entirely through these tests.
#![forbid(unsafe_code)]

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::elliptic_curve::PrimeField;

    fn keypair(seed: u8) -> ([u8; 32], Vec<u8>) {
        let private = [seed; 32];
        let signing = SigningKey::from_slice(&private).unwrap();
        let public = signing
            .verifying_key()
            .as_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        (private, public)
    }

    // TST-SEC-001: a member's SIGHASH_SINGLE component is lifted into a malicious non-session
    // transaction. Mitigation: the secure channel binds the component to its session, so it
    // cannot be opened (used) under any other binding.
    #[test]
    fn tst_sec_001_sighash_single_lift_prevented() {
        use session::SecureChannel;
        let component = b"member SIGHASH_SINGLE input-output";
        let session_binding = b"session-A-broadcaster-output";
        let envelope = SecureChannel::seal(component, session_binding);
        assert!(
            SecureChannel::open(&envelope, session_binding).is_some(),
            "valid in its own session"
        );
        assert!(
            SecureChannel::open(&envelope, b"malicious-non-session-tx").is_none(),
            "lift into another transaction is rejected"
        );
    }

    // TST-SEC-002: SIGHASH_SINGLE with input index >= output count (the "1" hash bug).
    // Mitigation: the sighash refuses it with a typed error (REQ-BSV-031).
    #[test]
    fn tst_sec_002_sighash_single_index_bug_refused() {
        use bsv::{
            p2pkh, OutPoint, Transaction, TxIn, TxOut, Txid, SIGHASH_FORKID, SIGHASH_SINGLE,
        };
        let outpoint = OutPoint {
            txid: Txid::from_display_hex(&"11".repeat(32)).unwrap(),
            vout: 0,
        };
        let tx = Transaction {
            version: 1,
            inputs: vec![
                TxIn {
                    outpoint,
                    unlocking_script: Vec::new(),
                    sequence: 0xFFFF_FFFF,
                },
                TxIn {
                    outpoint,
                    unlocking_script: Vec::new(),
                    sequence: 0xFFFF_FFFF,
                },
            ],
            outputs: vec![TxOut {
                value: 1,
                locking_script: p2pkh(&[0u8; 20]),
            }],
            locktime: 0,
        };
        // input index 1 has no corresponding output (only one output) -> refused
        assert!(bsv::sighash(
            &tx,
            1,
            &p2pkh(&[0u8; 20]),
            1,
            SIGHASH_SINGLE | SIGHASH_FORKID
        )
        .is_err());
    }

    // TST-SEC-003: broadcaster equivocation — different OP_RETURN rekeying keys to different
    // members. Mitigation: the echo-broadcast round localizes the equivocating sender.
    #[test]
    fn tst_sec_003_broadcaster_equivocation_detected() {
        use custody::echo::{run_echo_round, EchoOutcome, PartyView};
        // sender 0 (the broadcaster) sent a different round-one message to receiver 1
        let view0 = PartyView {
            receiver: 0,
            messages: vec![b"rekey-A".to_vec(), b"m1".to_vec()],
        };
        let view1 = PartyView {
            receiver: 1,
            messages: vec![b"rekey-B".to_vec(), b"m1".to_vec()],
        };
        assert_eq!(
            run_echo_round(&[view0, view1]),
            EchoOutcome::Equivocator(0),
            "the equivocating broadcaster is identified"
        );
    }

    // TST-SEC-004: session/rekeying-message replay. Mitigation: a per-request nonce is
    // recorded; a replayed nonce is rejected.
    #[test]
    fn tst_sec_004_replay_rejected() {
        use api::NonceStore;
        let mut nonces = NonceStore::new();
        assert!(nonces.check_and_record("member", 7), "first use accepted");
        assert!(
            !nonces.check_and_record("member", 7),
            "replayed nonce rejected"
        );
    }

    // TST-SEC-005: member griefing by withholding a signature. Mitigation: the broadcaster
    // proceeds with the remaining quorum (tolerates up to n-k unavailable).
    #[test]
    fn tst_sec_005_griefing_tolerated() {
        use res::{check_quorum, ResError};
        // 2-of-3: one griefer withholds -> 2 available -> proceed; two withhold -> fail cleanly
        assert!(
            check_quorum(2, 2, 3).is_ok(),
            "broadcaster proceeds without one griefer"
        );
        assert_eq!(
            check_quorum(1, 2, 3),
            Err(ResError::BelowQuorum),
            "below quorum fails cleanly, no partial state"
        );
    }

    // TST-SEC-006 (NEGATIVE): a module holding only the first seed + position tries to obtain
    // the second-function (obfuscation) key. Mitigation: seed isolation under hardened
    // derivation — the wrong seed yields a different key that cannot de-obfuscate.
    #[test]
    fn tst_sec_006_seed_isolation_breach_fails() {
        use overlay::{deobfuscate, obfuscate, resolve_key, signal_position, Position};
        let coords = signal_position(&Position::new(vec![1, 2, 3]));
        let first_seed = [0x11u8; 32];
        let second_seed = [0x22u8; 32];
        let second_key = resolve_key(&coords, &second_seed).unwrap();
        let ciphertext = obfuscate(&second_key, b"node payload").unwrap();

        // legitimate holder of the second seed de-obfuscates
        assert_eq!(
            deobfuscate(&second_key, &ciphertext).unwrap().expose(),
            b"node payload"
        );
        // a module with only the first seed derives a different key and cannot de-obfuscate
        let attacker_key = resolve_key(&coords, &first_seed).unwrap();
        assert!(
            deobfuscate(&attacker_key, &ciphertext).is_err(),
            "first seed cannot recover the second-function key"
        );
    }

    // TST-SEC-007: a revoked member tries to regain access. Mitigation: the eligibility check
    // (spent/timeout) keeps it ineligible and a re-spend cannot extend an exhausted sub.
    #[test]
    fn tst_sec_007_revoked_member_stays_out() {
        use session::{Subscription, SubscriptionMode};
        let mut sub = Subscription::new(SubscriptionMode::OffChain, 200, 100).unwrap();
        assert_eq!(sub.sessions_funded(), 2);
        sub.renew().unwrap();
        sub.renew().unwrap();
        assert!(
            sub.renew().is_err(),
            "exhausted subscription cannot be re-spent into a new session"
        );
        assert!(
            sub.is_revoked(3),
            "past the funded window the member is revoked"
        );
    }

    // TST-SEC-008: transaction malleability via a high-S signature. Mitigation: low-S is
    // enforced — a high-S encoding is rejected by verification (REQ-BSV-032).
    #[test]
    fn tst_sec_008_high_s_rejected() {
        use k256::ecdsa::Signature;
        let (private, public) = keypair(0x33);
        let prehash = [0x99u8; 32];
        let der = ckd::sign_prehash_der(&private, &prehash).unwrap();
        assert!(
            ckd::verify_der_prehash(&public, &prehash, &der),
            "the honest low-S signature verifies"
        );

        // flip S to n - S (high-S) and re-encode: verification must reject it
        let signature = Signature::from_der(&der).unwrap();
        let high_s = -*signature.s();
        let malleable = Signature::from_scalars(signature.r().to_repr(), high_s.to_repr()).unwrap();
        assert!(
            !ckd::verify_der_prehash(&public, &prehash, malleable.to_der().as_bytes()),
            "the high-S malleated signature is rejected"
        );
    }

    // TST-SEC-009: api auth replay/forgery — unsigned, replayed, and expired requests.
    // Mitigation: signature verification + nonce + expiry (REQ-API-003).
    #[test]
    fn tst_sec_009_api_auth_replay_and_forgery() {
        use api::{
            ApiConfig, ApiService, Backend, CallerRegistry, Operation, OperationResponse, Request,
        };
        use bsv::HeaderChain;

        struct Noop;
        impl Backend for Noop {
            fn execute(
                &mut self,
                _op: Operation,
                _payload: &[u8],
            ) -> Result<OperationResponse, api::ApiError> {
                Ok(OperationResponse::plain(Vec::new()))
            }
        }
        let (private, public) = keypair(0x44);
        let mut callers = CallerRegistry::new();
        callers.register("svc", &public);
        let config = ApiConfig {
            max_payload_bytes: 1024,
            rate_limit_per_window: 100,
            rate_window_secs: 60,
            op_timeout_millis: 1000,
        };
        let mut service = ApiService::new(config, callers, HeaderChain::new(0), Noop).unwrap();

        let mut signed = Request {
            caller: "svc".to_owned(),
            operation: Operation::CustodyKeygen,
            payload: vec![1],
            position: None,
            nonce: 1,
            expiry_unix: 10_000,
            signature: Vec::new(),
        };
        signed.signature = ckd::sign_prehash_der(&private, &signed.signing_prehash()).unwrap();
        assert!(
            service.handle(&signed, 1_000).is_ok(),
            "valid signed request accepted"
        );
        assert_eq!(
            service.handle(&signed, 1_000),
            Err(api::ApiError::Replay),
            "replayed nonce rejected"
        );

        let mut forged = signed.clone();
        forged.nonce = 2;
        forged.signature = vec![0u8; 8];
        assert_eq!(
            service.handle(&forged, 1_000),
            Err(api::ApiError::Unauthorized),
            "forged signature rejected"
        );

        let mut expired = Request {
            caller: "svc".to_owned(),
            operation: Operation::CustodyKeygen,
            payload: vec![1],
            position: None,
            nonce: 3,
            expiry_unix: 500,
            signature: Vec::new(),
        };
        expired.signature = ckd::sign_prehash_der(&private, &expired.signing_prehash()).unwrap();
        assert_eq!(
            service.handle(&expired, 1_000),
            Err(api::ApiError::Expired),
            "expired request rejected"
        );
    }

    // TST-SEC-031: secret leakage via Debug/serialization. Mitigation: SecretBytes (and
    // share material) redact in Debug; metrics never carry a secret value.
    #[test]
    fn tst_sec_031_no_secret_leakage() {
        use kst::split;
        use obs::Metrics;
        use secmem::SecretBytes;

        let secret = SecretBytes::from_slice(b"super-secret-seed-value");
        let rendered = format!("{secret:?}");
        assert!(
            rendered.contains("redacted"),
            "SecretBytes redacts in Debug"
        );
        assert!(
            !rendered.contains("super-secret-seed-value"),
            "no secret in Debug"
        );

        let shares = split(b"master-seed-bytes-32-xxxxxxxxxxxx", 2, 3).unwrap();
        assert!(
            format!("{:?}", shares[0]).contains("redacted"),
            "share material redacts in Debug"
        );

        let metrics = Metrics::new().unwrap();
        metrics.record_operation("custody.keygen", "ok", 0.01);
        assert!(
            !metrics.render().unwrap().contains("seed"),
            "no secret token in metrics output"
        );
    }

    // TST-SEC-100: resource exhaustion — oversized payload and oversized graph. Mitigation:
    // validated bounds reject each with a typed error and no OOM/panic.
    #[test]
    fn tst_sec_100_resource_exhaustion_bounded() {
        use api::{
            ApiConfig, ApiService, Backend, CallerRegistry, Operation, OperationResponse, Request,
        };
        use bsv::HeaderChain;
        use keygraph::{Bounds, KeyGraph};

        // oversized api payload -> typed Oversize
        struct Noop;
        impl Backend for Noop {
            fn execute(
                &mut self,
                _op: Operation,
                _payload: &[u8],
            ) -> Result<OperationResponse, api::ApiError> {
                Ok(OperationResponse::plain(Vec::new()))
            }
        }
        let config = ApiConfig {
            max_payload_bytes: 16,
            rate_limit_per_window: 100,
            rate_window_secs: 60,
            op_timeout_millis: 1000,
        };
        let mut service =
            ApiService::new(config, CallerRegistry::new(), HeaderChain::new(0), Noop).unwrap();
        let oversize = Request {
            caller: "x".to_owned(),
            operation: Operation::Health,
            payload: vec![0u8; 4096],
            position: None,
            nonce: 1,
            expiry_unix: 0,
            signature: Vec::new(),
        };
        assert_eq!(
            service.handle(&oversize, 0),
            Err(api::ApiError::Oversize),
            "oversized payload rejected"
        );

        // oversized graph -> bounded add_child rejects beyond the configured breadth
        let mut graph = KeyGraph::with_root(Bounds {
            max_depth: 4,
            max_breadth: 2,
            max_nodes: 8,
        });
        let root = graph.root();
        assert!(graph.add_child(root, 0).is_ok());
        assert!(graph.add_child(root, 1).is_ok());
        assert!(
            graph.add_child(root, 2).is_err(),
            "exceeding max breadth is rejected, not an OOM"
        );

        // a hostile script does not panic the parser (typed result)
        let _ = bsv::parse_script(&vec![0x6au8; 100_000]);
    }
}
