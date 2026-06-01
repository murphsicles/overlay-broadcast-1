//! GG20 type-7 fault attribution (REQ-CUS-004 — the final identifiable-abort case). If a
//! run passes every MtA proof yet the combined signature `(r, s)` still fails to verify,
//! some party broadcast a final share `s_i ≠ m·k_i + r·σ_i` that is inconsistent with the
//! `k_i` and `σ_i` it actually used. Each party publishes EC commitments `K_i = k_i·G` and
//! `Σ_i = σ_i·G` (the GG20 phase-6 broadcasts) alongside its `s_i`; the relation
//! `s_i·G = m·K_i + r·Σ_i` is checkable in the clear and pinpoints the offending party.
//!
//! This attributes a dishonest *final share* against the published per-party commitments.
//! Binding those commitments all the way back to the MtA transcript (so a party cannot also
//! lie about `K_i`/`Σ_i`) is the consistency proof already enforced earlier in the protocol
//! (the range and responder proofs); see `docs/ARCHITECTURE.md`.
use k256::{ProjectivePoint, Scalar};

/// One party's type-7 evidence: EC commitments to its `k` and `σ` shares plus its broadcast
/// final share.
#[derive(Clone, Debug)]
pub struct ShareEvidence {
    /// `K_i = k_i·G`.
    pub k_commitment: ProjectivePoint,
    /// `Σ_i = σ_i·G`.
    pub sigma_commitment: ProjectivePoint,
    /// The broadcast final share `s_i`.
    pub s_share: Scalar,
}

impl ShareEvidence {
    /// Build honest evidence from the party's actual shares (used by honest parties and in
    /// tests): `K_i = k_i·G`, `Σ_i = σ_i·G`, `s_i = m·k_i + r·σ_i`.
    #[must_use]
    pub fn from_shares(k_share: Scalar, sigma_share: Scalar, m: Scalar, r: Scalar) -> Self {
        Self {
            k_commitment: ProjectivePoint::GENERATOR * k_share,
            sigma_commitment: ProjectivePoint::GENERATOR * sigma_share,
            s_share: m * k_share + r * sigma_share,
        }
    }
}

/// The outcome of the type-7 check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type7Outcome {
    /// Every final share is consistent with its commitments; the fault lies elsewhere.
    Consistent,
    /// The party at this index broadcast a final share inconsistent with its commitments.
    Faulty(usize),
}

/// Check every party's final share against its commitments: `s_i·G == m·K_i + r·Σ_i`. The
/// first party that fails is the identifiable type-7 culprit.
#[must_use]
pub fn verify_final_shares(evidence: &[ShareEvidence], m: Scalar, r: Scalar) -> Type7Outcome {
    for (index, party) in evidence.iter().enumerate() {
        let claimed = ProjectivePoint::GENERATOR * party.s_share;
        let expected = party.k_commitment * m + party.sigma_commitment * r;
        if claimed != expected {
            return Type7Outcome::Faulty(index);
        }
    }
    Type7Outcome::Consistent
}
