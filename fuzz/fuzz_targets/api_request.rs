//! libFuzzer target for the api request path (REQ-FUZ-004): adversarial signature/payload
//! bytes must never panic, only produce typed rejections.
#![no_main]

use api::{ApiConfig, ApiError, ApiService, Backend, CallerRegistry, Operation, OperationResponse, Request};
use bsv::HeaderChain;
use libfuzzer_sys::fuzz_target;

struct NoopBackend;
impl Backend for NoopBackend {
    fn execute(&mut self, _operation: Operation, _payload: &[u8]) -> Result<OperationResponse, ApiError> {
        Ok(OperationResponse::plain(Vec::new()))
    }
}

fuzz_target!(|data: &[u8]| {
    let mid = data.len() / 2;
    let (payload, signature) = data.split_at(mid);
    let mut callers = CallerRegistry::new();
    callers.register("svc", &[0x02u8; 33]);
    let config = ApiConfig { max_payload_bytes: 1_000_000, rate_limit_per_window: u32::MAX, rate_window_secs: 60, op_timeout_millis: 10_000 };
    if let Ok(mut service) = ApiService::new(config, callers, HeaderChain::new(0), NoopBackend) {
        let request = Request {
            caller: "svc".to_owned(),
            operation: Operation::OverlayWrite,
            payload: payload.to_vec(),
            position: None,
            nonce: 1,
            expiry_unix: 1_000_000,
            signature: signature.to_vec(),
        };
        let _ = service.handle(&request, 1_000);
    }
});
