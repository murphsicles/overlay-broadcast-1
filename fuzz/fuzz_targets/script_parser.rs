//! libFuzzer target for the script parser (REQ-FUZ-002).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bsv::parse_script(data);
});
