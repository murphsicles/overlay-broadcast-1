//! Session transaction construction and the SIGHASH discipline (GB §6.1.1.3, §6.5;
//! REQ-SES-001/002/003). For each eligible member there is a member input and a
//! corresponding member output (bare multisig `OP_1 <P_M> <P_B> OP_2
//! OP_CHECKMULTISIG`, spendable by member or broadcaster); plus a broadcaster input
//! and output; plus an `OP_FALSE OP_RETURN` output carrying the rekeying metadata.
//! Members sign SIGHASH_SINGLE (their own output only); the broadcaster signs LAST
//! under SIGHASH_ALL over every output including the OP_RETURN.
use crate::error::SesError;
use bsv::{
    bare_multisig_1_of_2, build_data_carrier, hash160, p2pkh, parse_script, push_data, sighash,
    Hash256, OutPoint, ScriptOp, Transaction, TxIn, TxOut, SIGHASH_ALL, SIGHASH_FORKID,
    SIGHASH_SINGLE,
};

const SEQ_FINAL: u32 = 0xffff_ffff;
const MEMBER_FLAG: u8 = SIGHASH_SINGLE | SIGHASH_FORKID;
const BROADCASTER_FLAG: u8 = SIGHASH_ALL | SIGHASH_FORKID;

/// One eligible member's contribution to a session.
#[derive(Clone, Debug)]
pub struct MemberSpec {
    /// The member's public key (compressed).
    pub member_pubkey: [u8; 33],
    /// The outpoint the member spends as its input.
    pub funding: OutPoint,
    /// The value (minor units) of the output the member spends.
    pub input_value: u64,
    /// The value placed on the member's session output.
    pub output_value: u64,
}

/// The broadcaster's parameters and the rekeying payload.
#[derive(Clone, Debug)]
pub struct SessionParams {
    /// The broadcaster public key (compressed).
    pub broadcaster_pubkey: [u8; 33],
    /// The broadcaster's input outpoint.
    pub broadcaster_funding: OutPoint,
    /// The value of the output the broadcaster spends.
    pub broadcaster_input_value: u64,
    /// The value on the broadcaster's output.
    pub broadcaster_output_value: u64,
    /// The OP_RETURN rekeying metadata (E(k_G^{r_j}) etc.).
    pub rekeying_payload: Vec<u8>,
}

/// A built session transaction.
#[derive(Clone, Debug)]
pub struct SessionTx {
    /// The transaction.
    pub transaction: Transaction,
    /// The number of members (their inputs/outputs occupy indices 0..member_count).
    pub member_count: usize,
}

impl SessionTx {
    /// The index of the broadcaster input and output.
    #[must_use]
    pub fn broadcaster_index(&self) -> usize {
        self.member_count
    }
}

/// Build a session transaction per GB Tables 1-2.
///
/// # Errors
/// [`SesError::BadStructure`] if there are no members.
pub fn build_session(
    members: &[MemberSpec],
    params: &SessionParams,
) -> Result<SessionTx, SesError> {
    if members.is_empty() {
        return Err(SesError::BadStructure);
    }
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();
    for member in members {
        inputs.push(input_for(member.funding));
        outputs.push(TxOut {
            value: member.output_value,
            locking_script: bare_multisig_1_of_2(&member.member_pubkey, &params.broadcaster_pubkey),
        });
    }
    inputs.push(input_for(params.broadcaster_funding));
    outputs.push(TxOut {
        value: params.broadcaster_output_value,
        locking_script: p2pkh(&hash160(&params.broadcaster_pubkey)),
    });
    outputs.push(build_data_carrier(&params.rekeying_payload));
    Ok(SessionTx {
        transaction: Transaction {
            version: 1,
            inputs,
            outputs,
            locktime: 0,
        },
        member_count: members.len(),
    })
}

/// Sign a member input under SIGHASH_SINGLE (the member signs only its own output).
///
/// # Errors
/// [`SesError`] on a sighash or signing failure (incl. SIGHASH_SINGLE index safety).
pub fn sign_member(
    tx: &mut Transaction,
    index: usize,
    member_priv: &[u8; 32],
    member_pubkey: &[u8; 33],
    input_value: u64,
) -> Result<(), SesError> {
    let digest = member_digest(tx, index, member_pubkey, input_value)?;
    apply_unlock(tx, index, member_priv, member_pubkey, &digest, MEMBER_FLAG)
}

/// Sign the broadcaster input LAST under SIGHASH_ALL (covering every output,
/// including the OP_RETURN), GB §6.5.
///
/// # Errors
/// [`SesError`] on a sighash or signing failure.
pub fn sign_broadcaster(
    tx: &mut Transaction,
    index: usize,
    broadcaster_priv: &[u8; 32],
    broadcaster_pubkey: &[u8; 33],
    input_value: u64,
) -> Result<(), SesError> {
    let prev = p2pkh(&hash160(broadcaster_pubkey));
    let digest = sighash(tx, index, &prev, input_value, BROADCASTER_FLAG)?;
    apply_unlock(
        tx,
        index,
        broadcaster_priv,
        broadcaster_pubkey,
        &digest,
        BROADCASTER_FLAG,
    )
}

/// Verify a member's SIGHASH_SINGLE signature.
///
/// # Errors
/// [`SesError`] on a sighash/parse failure.
pub fn verify_member(
    tx: &Transaction,
    index: usize,
    member_pubkey: &[u8; 33],
    input_value: u64,
) -> Result<bool, SesError> {
    let digest = member_digest(tx, index, member_pubkey, input_value)?;
    verify_unlock(tx, index, &digest)
}

/// Verify the broadcaster's SIGHASH_ALL signature.
///
/// # Errors
/// [`SesError`] on a sighash/parse failure.
pub fn verify_broadcaster(
    tx: &Transaction,
    index: usize,
    broadcaster_pubkey: &[u8; 33],
    input_value: u64,
) -> Result<bool, SesError> {
    let prev = p2pkh(&hash160(broadcaster_pubkey));
    let digest = sighash(tx, index, &prev, input_value, BROADCASTER_FLAG)?;
    verify_unlock(tx, index, &digest)
}

fn member_digest(
    tx: &Transaction,
    index: usize,
    member_pubkey: &[u8; 33],
    input_value: u64,
) -> Result<Hash256, SesError> {
    let prev = p2pkh(&hash160(member_pubkey));
    Ok(sighash(tx, index, &prev, input_value, MEMBER_FLAG)?)
}

fn input_for(funding: OutPoint) -> TxIn {
    TxIn {
        outpoint: funding,
        unlocking_script: Vec::new(),
        sequence: SEQ_FINAL,
    }
}

fn apply_unlock(
    tx: &mut Transaction,
    index: usize,
    private_key: &[u8; 32],
    public_key: &[u8; 33],
    digest: &Hash256,
    flag: u8,
) -> Result<(), SesError> {
    let mut signature = ckd::sign_prehash_der(private_key, digest.internal())?;
    signature.push(flag);
    let mut unlock = Vec::new();
    push_data(&mut unlock, &signature);
    push_data(&mut unlock, public_key);
    let input = tx.inputs.get_mut(index).ok_or(SesError::BadIndex)?;
    input.unlocking_script = unlock;
    Ok(())
}

fn verify_unlock(tx: &Transaction, index: usize, digest: &Hash256) -> Result<bool, SesError> {
    let input = tx.inputs.get(index).ok_or(SesError::BadIndex)?;
    match parse_script(&input.unlocking_script)?.as_slice() {
        [ScriptOp::Push(sig_with_flag), ScriptOp::Push(public_key)] => {
            let der_len = sig_with_flag
                .len()
                .checked_sub(1)
                .ok_or(SesError::BadStructure)?;
            let signature_der = sig_with_flag.get(..der_len).ok_or(SesError::BadStructure)?;
            Ok(ckd::verify_der_prehash(
                public_key,
                digest.internal(),
                signature_der,
            ))
        }
        _ => Ok(false),
    }
}
