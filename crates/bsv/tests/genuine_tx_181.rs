//! Genuine-data transaction round-trip against the two real transactions in BSV
//! mainnet block 181 (REQ-BSV-011/012/013). The raw bytes were retrieved from a
//! public BSV node API (WhatsOnChain `/v1/bsv/main/tx/<txid>/hex`) and are the
//! authoritative on-chain bytes; the txids match crates/bsv/fixtures/block_000181.json.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use bsv::{hex_to_bytes, Transaction};

const TX0_HEX: &str = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0128ffffffff0100f2052a0100000043410435f0d8366085f73906a48309728155532f24293ea59fe0b33a245c4b8d75f82c3e70804457b7f49322aa822196a7521e4931f809d7e489bccb4ff14758d170e5ac00000000";
const TX0_ID: &str = "8347cee4a1cb5ad1bb0d92e86e6612dbf6cfc7649c9964f210d4069b426e720a";

const TX1_HEX: &str = "0100000001169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f40100000048473044022027542a94d6646c51240f23a76d33088d3dd8815b25e9ea18cac67d1171a3212e02203baf203c6e7b80ebd3e588628466ea28be572fe1aaa3f30947da4763dd3b3d2b01ffffffff0200ca9a3b00000000434104b5abd412d4341b45056d3e376cd446eca43fa871b51961330deebd84423e740daa520690e1d9e074654c59ff87b408db903649623e86f1ca5412786f61ade2bfac005ed0b20000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
const TX1_ID: &str = "a16f3ce4dd5deb92d98ef5cf8afeaf0775ebca408f708b2146c4fb42b41e14be";

fn check_roundtrip(hex: &str, expected_txid: &str) -> Transaction {
    let raw = hex_to_bytes(hex).unwrap();
    let tx = Transaction::parse(&raw).unwrap();
    assert_eq!(
        tx.serialize().unwrap(),
        raw,
        "re-serialise is byte-identical"
    );
    assert_eq!(tx.txid().unwrap().to_display_hex(), expected_txid);
    tx
}

// TST-BSV-011/013: parse genuine transactions, re-serialise byte-identically, and
// recompute the genuine txids.
#[test]
fn genuine_coinbase_roundtrip_and_txid() {
    let tx = check_roundtrip(TX0_HEX, TX0_ID);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.inputs[0].outpoint.vout, 0xffff_ffff); // coinbase null outpoint
    assert_eq!(tx.outputs.len(), 1);
    assert_eq!(tx.outputs[0].value, 5_000_000_000); // 50.00 coinbase in minor units
}

#[test]
fn genuine_spend_roundtrip_and_txid() {
    let tx = check_roundtrip(TX1_HEX, TX1_ID);
    assert_eq!(tx.inputs.len(), 1);
    assert_eq!(tx.outputs.len(), 2);
    assert_eq!(tx.outputs[0].value, 1_000_000_000);
}

// TST-BSV-012: the parser rejects truncation, emptiness, and trailing bytes without
// panicking.
#[test]
fn defensive_parse_rejects_malformed() {
    let raw = hex_to_bytes(TX1_HEX).unwrap();
    assert!(Transaction::parse(&raw[..raw.len() - 5]).is_err());
    assert!(Transaction::parse(&[]).is_err());
    let mut trailing = raw.clone();
    trailing.push(0xff);
    assert!(Transaction::parse(&trailing).is_err());
}
