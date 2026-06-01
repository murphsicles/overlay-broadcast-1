//! libFuzzer target for the OP_RETURN rekeying-payload / data-item parser (REQ-FUZ-005):
//! the on-chain data-carrier parser is the untrusted-input boundary for rekeying payloads.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bsv::parse_data_carrier(data);
});
