//! Transaction model with a defensive parser and byte-exact serializer
//! (REQ-BSV-011/012/013). BSV has no separate witness structure; the full
//! transaction is hashed.
use crate::bytes::{write_varint, Cursor};
use crate::error::BsvError;
use crate::hash::double_sha256;
use crate::txid::Txid;

/// Upper bound on inputs/outputs accepted from untrusted input (REQ-GOV-013).
const MAX_IO: u64 = 10_000_000;

/// A reference to a previous output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutPoint {
    /// The funding transaction id.
    pub txid: Txid,
    /// The output index within that transaction.
    pub vout: u32,
}

/// A transaction input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxIn {
    /// The output being spent.
    pub outpoint: OutPoint,
    /// The unlocking (scriptSig) bytes.
    pub unlocking_script: Vec<u8>,
    /// The sequence number.
    pub sequence: u32,
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxOut {
    /// The value in minor units.
    pub value: u64,
    /// The locking (scriptPubKey) bytes.
    pub locking_script: Vec<u8>,
}

/// A BSV transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// Transaction version.
    pub version: i32,
    /// Inputs.
    pub inputs: Vec<TxIn>,
    /// Outputs.
    pub outputs: Vec<TxOut>,
    /// Locktime.
    pub locktime: u32,
}

impl Transaction {
    /// Parse raw transaction bytes, rejecting malformed/truncated/trailing input.
    ///
    /// # Errors
    /// [`BsvError::MalformedTx`] / [`BsvError::Truncated`] / [`BsvError::OutOfRange`].
    pub fn parse(raw: &[u8]) -> Result<Self, BsvError> {
        let mut cur = Cursor::new(raw);
        let version = cur.i32_le()?;
        let inputs = parse_vec(&mut cur, parse_input)?;
        let outputs = parse_vec(&mut cur, parse_output)?;
        let locktime = cur.u32_le()?;
        if !cur.is_empty() {
            return Err(BsvError::MalformedTx);
        }
        Ok(Self {
            version,
            inputs,
            outputs,
            locktime,
        })
    }

    /// Serialise to raw bytes (byte-identical round-trip with [`Transaction::parse`]).
    ///
    /// # Errors
    /// [`BsvError::OutOfRange`] if a count exceeds `u64`.
    pub fn serialize(&self) -> Result<Vec<u8>, BsvError> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        write_varint(&mut out, count(self.inputs.len())?);
        for input in &self.inputs {
            serialize_input(&mut out, input)?;
        }
        write_varint(&mut out, count(self.outputs.len())?);
        for output in &self.outputs {
            serialize_output(&mut out, output)?;
        }
        out.extend_from_slice(&self.locktime.to_le_bytes());
        Ok(out)
    }

    /// The transaction id: double-SHA-256 of the canonical serialization.
    ///
    /// # Errors
    /// Propagates [`Transaction::serialize`] errors.
    pub fn txid(&self) -> Result<Txid, BsvError> {
        Ok(Txid::from_hash(double_sha256(&self.serialize()?)))
    }
}

fn parse_vec<T, F>(cur: &mut Cursor<'_>, mut parse_one: F) -> Result<Vec<T>, BsvError>
where
    F: FnMut(&mut Cursor<'_>) -> Result<T, BsvError>,
{
    let n = cur.varint()?;
    if n > MAX_IO {
        return Err(BsvError::MalformedTx);
    }
    // No capacity reservation from an untrusted count; each item consumes bytes, so
    // the loop is bounded by the input length.
    let mut out = Vec::new();
    let mut i = 0u64;
    while i < n {
        out.push(parse_one(cur)?);
        i = i.checked_add(1).ok_or(BsvError::OutOfRange)?;
    }
    Ok(out)
}

fn parse_input(cur: &mut Cursor<'_>) -> Result<TxIn, BsvError> {
    let txid = Txid::from_hash(cur.hash256()?);
    let vout = cur.u32_le()?;
    let unlocking_script = cur.varint_bytes()?.to_vec();
    let sequence = cur.u32_le()?;
    Ok(TxIn {
        outpoint: OutPoint { txid, vout },
        unlocking_script,
        sequence,
    })
}

fn parse_output(cur: &mut Cursor<'_>) -> Result<TxOut, BsvError> {
    let value = cur.u64_le()?;
    let locking_script = cur.varint_bytes()?.to_vec();
    Ok(TxOut {
        value,
        locking_script,
    })
}

fn serialize_input(out: &mut Vec<u8>, input: &TxIn) -> Result<(), BsvError> {
    out.extend_from_slice(input.outpoint.txid.as_hash().internal());
    out.extend_from_slice(&input.outpoint.vout.to_le_bytes());
    write_varint(out, count(input.unlocking_script.len())?);
    out.extend_from_slice(&input.unlocking_script);
    out.extend_from_slice(&input.sequence.to_le_bytes());
    Ok(())
}

fn serialize_output(out: &mut Vec<u8>, output: &TxOut) -> Result<(), BsvError> {
    out.extend_from_slice(&output.value.to_le_bytes());
    write_varint(out, count(output.locking_script.len())?);
    out.extend_from_slice(&output.locking_script);
    Ok(())
}

fn count(len: usize) -> Result<u64, BsvError> {
    u64::try_from(len).map_err(|_| BsvError::OutOfRange)
}
