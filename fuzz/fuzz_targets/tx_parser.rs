//! libFuzzer target for the transaction parser (REQ-FUZ-001). Any crash is committed as a
//! regression seed and mirrored as a stable test in `crates/fuzzprop`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bsv::Transaction::parse(data);
});
