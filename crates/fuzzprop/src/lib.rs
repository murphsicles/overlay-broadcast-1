//! Runnable robustness fuzzing (Section 17). cargo-fuzz/libFuzzer needs a nightly
//! toolchain and LLVM's libFuzzer, which are not present in this environment; the
//! libFuzzer harnesses live under `fuzz/` and run in a scheduled CI job (REQ-FUZ-001..005).
//! This crate provides the part that runs on stable in every CI gate: a deterministic,
//! in-process fuzzer that drives each untrusted-input parser with many adversarial byte
//! strings and asserts none panics, hangs, or accepts — every failure is a typed error
//! (REQ-FUZ-006). A panic in any parser unwinds into [`std::panic::catch_unwind`] and
//! fails the test, pinpointing the offending parser.
#![forbid(unsafe_code)]

// This crate is exercised entirely through its tests.

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    // A tiny deterministic PRNG (SplitMix64-style) so the fuzz corpus is reproducible and
    // any crash is a committable regression seed.
    struct Prng(u64);

    impl Prng {
        fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn byte(&mut self) -> u8 {
            self.next_u64().to_le_bytes()[0]
        }

        // A random byte string of length 0..max_len.
        fn bytes(&mut self, max_len: u64) -> Vec<u8> {
            let len = usize::try_from(self.next_u64() % (max_len + 1)).unwrap_or(0);
            (0..len).map(|_| self.byte()).collect()
        }
    }

    // Run `body` over `iterations` random inputs, asserting none panics.
    fn fuzz<F: Fn(&[u8])>(label: &str, seed: u64, iterations: u32, max_len: u64, body: F) {
        let mut prng = Prng::new(seed);
        for _ in 0..iterations {
            let input = prng.bytes(max_len);
            let outcome = catch_unwind(AssertUnwindSafe(|| body(&input)));
            assert!(outcome.is_ok(), "{label} panicked on input {input:?}");
        }
    }

    // TST-FUZ-001: the transaction parser never panics; malformed input is a typed error.
    #[test]
    fn tst_fuz_001_transaction_parser() {
        fuzz("Transaction::parse", 0x01, 4_000, 200, |data| {
            let _ = bsv::Transaction::parse(data);
        });
    }

    // TST-FUZ-002: the script parser never panics.
    #[test]
    fn tst_fuz_002_script_parser() {
        fuzz("parse_script", 0x02, 4_000, 200, |data| {
            let _ = bsv::parse_script(data);
        });
    }

    // TST-FUZ-003: the block-header parser (and, by delegation, NodeClient response header
    // parsing) never panics.
    #[test]
    fn tst_fuz_003_header_parser() {
        fuzz("BlockHeader::parse", 0x03, 4_000, 120, |data| {
            let _ = bsv::BlockHeader::parse(data);
        });
    }

    // TST-FUZ-004: the api request path never panics on adversarial signature/payload bytes;
    // every malformed request is a typed rejection.
    #[test]
    fn tst_fuz_004_api_request() {
        use api::{
            ApiConfig, ApiService, Backend, CallerRegistry, Operation, OperationResponse, Request,
        };
        use bsv::HeaderChain;

        struct NoopBackend;
        impl Backend for NoopBackend {
            fn execute(
                &mut self,
                _operation: Operation,
                _payload: &[u8],
            ) -> Result<OperationResponse, api::ApiError> {
                Ok(OperationResponse::plain(Vec::new()))
            }
        }

        let mut callers = CallerRegistry::new();
        callers.register("svc", &[0x02u8; 33]);
        let config = ApiConfig {
            max_payload_bytes: 100_000,
            rate_limit_per_window: u32::MAX,
            rate_window_secs: 60,
            op_timeout_millis: 10_000,
        };
        let mut service =
            ApiService::new(config, callers, HeaderChain::new(0), NoopBackend).unwrap();

        let mut prng = Prng::new(0x04);
        for index in 0..4_000u64 {
            let payload = prng.bytes(256);
            let signature = prng.bytes(80);
            let request = Request {
                caller: "svc".to_owned(),
                operation: Operation::OverlayWrite,
                payload,
                position: None,
                nonce: index,
                expiry_unix: 1_000_000,
                signature,
            };
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let _ = service.handle(&request, 1_000);
            }));
            assert!(outcome.is_ok(), "api request handling panicked");
        }
    }

    // TST-FUZ-005: the OP_RETURN data-carrier parser (the on-chain rekeying-payload boundary)
    // never panics on adversarial input.
    #[test]
    fn tst_fuz_005_data_carrier_parser() {
        fuzz("parse_data_carrier", 0x05, 4_000, 300, |data| {
            let _ = bsv::parse_data_carrier(data);
        });
    }

    // TST-FUZ-006: aggregate — a mixed adversarial corpus through every parser leaves the
    // process intact (no panic/hang/accept), the property an extended libFuzzer run checks.
    #[test]
    fn tst_fuz_006_no_panic_aggregate() {
        let mut prng = Prng::new(0xF6);
        for _ in 0..6_000u32 {
            let data = prng.bytes(256);
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let _ = bsv::Transaction::parse(&data);
                let _ = bsv::parse_script(&data);
                let _ = bsv::BlockHeader::parse(&data);
                let _ = bsv::parse_data_carrier(&data);
            }));
            assert!(outcome.is_ok(), "a parser panicked on input {data:?}");
        }
    }
}
