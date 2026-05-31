//! BSV FORKID sighash (BIP143-style with the fork id), for SIGHASH_ALL / SINGLE /
//! NONE and the ANYONECANPAY combinations (REQ-BSV-030/031).
use crate::bytes::write_varint;
use crate::error::BsvError;
use crate::hash::{double_sha256, Hash256};
use crate::transaction::{Transaction, TxOut};

/// Sign all outputs.
pub const SIGHASH_ALL: u8 = 0x01;
/// Sign no outputs.
pub const SIGHASH_NONE: u8 = 0x02;
/// Sign only the output at the input's index.
pub const SIGHASH_SINGLE: u8 = 0x03;
/// Sign only this input.
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;
/// The BSV fork-id marker bit (always set on BSV).
pub const SIGHASH_FORKID: u8 = 0x40;

const ZERO: Hash256 = Hash256::from_internal([0u8; 32]);

/// Compute the FORKID sighash for `input_index`, spending an output whose locking
/// script is `script_code` and whose value is `value` minor units.
///
/// # Errors
/// [`BsvError::MalformedTx`] if the index is out of range; [`BsvError::SighashSingleIndex`]
/// for SIGHASH_SINGLE without a corresponding output (REQ-BSV-031).
pub fn sighash(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    value: u64,
    sighash_type: u8,
) -> Result<Hash256, BsvError> {
    let base = sighash_type & 0x1f;
    let anyone = (sighash_type & SIGHASH_ANYONECANPAY) != 0;
    let input = tx.inputs.get(input_index).ok_or(BsvError::MalformedTx)?;
    if base == SIGHASH_SINGLE && input_index >= tx.outputs.len() {
        return Err(BsvError::SighashSingleIndex);
    }

    let hash_prevouts = if anyone {
        ZERO
    } else {
        double_sha256(&prevouts(tx))
    };
    let hash_sequence = if anyone || base == SIGHASH_SINGLE || base == SIGHASH_NONE {
        ZERO
    } else {
        double_sha256(&sequences(tx))
    };
    let hash_outputs = outputs_hash(tx, base, input_index)?;

    let mut p: Vec<u8> = Vec::new();
    p.extend_from_slice(&tx.version.to_le_bytes());
    p.extend_from_slice(hash_prevouts.internal());
    p.extend_from_slice(hash_sequence.internal());
    p.extend_from_slice(input.outpoint.txid.as_hash().internal());
    p.extend_from_slice(&input.outpoint.vout.to_le_bytes());
    write_varint(
        &mut p,
        u64::try_from(script_code.len()).map_err(|_| BsvError::OutOfRange)?,
    );
    p.extend_from_slice(script_code);
    p.extend_from_slice(&value.to_le_bytes());
    p.extend_from_slice(&input.sequence.to_le_bytes());
    p.extend_from_slice(hash_outputs.internal());
    p.extend_from_slice(&tx.locktime.to_le_bytes());
    p.extend_from_slice(&u32::from(sighash_type).to_le_bytes());
    Ok(double_sha256(&p))
}

fn prevouts(tx: &Transaction) -> Vec<u8> {
    let mut out = Vec::new();
    for input in &tx.inputs {
        out.extend_from_slice(input.outpoint.txid.as_hash().internal());
        out.extend_from_slice(&input.outpoint.vout.to_le_bytes());
    }
    out
}

fn sequences(tx: &Transaction) -> Vec<u8> {
    let mut out = Vec::new();
    for input in &tx.inputs {
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    out
}

fn outputs_hash(tx: &Transaction, base: u8, input_index: usize) -> Result<Hash256, BsvError> {
    if base != SIGHASH_SINGLE && base != SIGHASH_NONE {
        let mut out = Vec::new();
        for output in &tx.outputs {
            serialize_output(&mut out, output)?;
        }
        Ok(double_sha256(&out))
    } else if base == SIGHASH_SINGLE {
        let output = tx
            .outputs
            .get(input_index)
            .ok_or(BsvError::SighashSingleIndex)?;
        let mut out = Vec::new();
        serialize_output(&mut out, output)?;
        Ok(double_sha256(&out))
    } else {
        Ok(ZERO)
    }
}

fn serialize_output(out: &mut Vec<u8>, output: &TxOut) -> Result<(), BsvError> {
    out.extend_from_slice(&output.value.to_le_bytes());
    write_varint(
        out,
        u64::try_from(output.locking_script.len()).map_err(|_| BsvError::OutOfRange)?,
    );
    out.extend_from_slice(&output.locking_script);
    Ok(())
}
