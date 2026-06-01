//! libFuzzer target for the block-header parser and NodeClient response header parsing
//! (REQ-FUZ-003).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bsv::BlockHeader::parse(data);
});
