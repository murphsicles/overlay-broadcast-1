//! OP_FALSE OP_RETURN data carrier at post-Genesis sizes (REQ-BSV-070, REQ-UNI-004).
use crate::error::BsvError;
use crate::script::{op, parse_script, push_data, ScriptOp};
use crate::transaction::TxOut;

/// Build a zero-value output carrying `payload` as `OP_FALSE OP_RETURN <payload>`.
#[must_use]
pub fn build_data_carrier(payload: &[u8]) -> TxOut {
    let mut locking_script = vec![op::FALSE, op::RETURN];
    push_data(&mut locking_script, payload);
    TxOut {
        value: 0,
        locking_script,
    }
}

/// Recover the payload from a data-carrier locking script.
///
/// # Errors
/// [`BsvError::MalformedScript`] if the script is not a recognised data carrier.
pub fn parse_data_carrier(script: &[u8]) -> Result<Vec<u8>, BsvError> {
    match parse_script(script)?.as_slice() {
        [ScriptOp::Op(op::FALSE), ScriptOp::Op(op::RETURN), ScriptOp::Push(payload)] => {
            Ok(payload.clone())
        }
        // An empty payload encodes as OP_0 (a zero-length push opcode) or as nothing.
        [ScriptOp::Op(op::FALSE), ScriptOp::Op(op::RETURN), ScriptOp::Op(op::FALSE)]
        | [ScriptOp::Op(op::FALSE), ScriptOp::Op(op::RETURN)] => Ok(Vec::new()),
        _ => Err(BsvError::MalformedScript),
    }
}
