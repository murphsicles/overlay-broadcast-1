//! Subscription lifecycle (GB §6.1; REQ-SES-010). Off-chain (nominal-fee) and
//! on-block models. A member's contribution `x` funds `k = x / mem_fee` sessions;
//! spending the member output into the next session transaction is renewal/consent,
//! and not spending by the deadline is revocation.
use crate::error::SesError;

/// Whether the subscription is settled off-chain (nominal fee) or on-block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionMode {
    /// Off-chain, nominal-fee subscription (GB §6.1).
    OffChain,
    /// On-block subscription.
    OnBlock,
}

/// A member subscription: a contribution that funds a number of sessions, renewed by
/// spending into each successive session transaction.
#[derive(Clone, Debug)]
pub struct Subscription {
    mode: SubscriptionMode,
    contribution: u64,
    mem_fee: u64,
    renewed: u64,
}

impl Subscription {
    /// Create a subscription from a contribution and the per-session member fee.
    ///
    /// # Errors
    /// [`SesError::BadFee`] if `mem_fee` is zero.
    pub fn new(mode: SubscriptionMode, contribution: u64, mem_fee: u64) -> Result<Self, SesError> {
        if mem_fee == 0 {
            return Err(SesError::BadFee);
        }
        Ok(Self {
            mode,
            contribution,
            mem_fee,
            renewed: 0,
        })
    }

    /// The number of sessions the contribution funds: `k = x / mem_fee` (REQ-SES-010).
    #[must_use]
    pub fn sessions_funded(&self) -> u64 {
        self.contribution / self.mem_fee
    }

    /// Renew (spend the member output into the next session). Consumes one funded
    /// session.
    ///
    /// # Errors
    /// [`SesError::Exhausted`] if no funded sessions remain.
    pub fn renew(&mut self) -> Result<(), SesError> {
        if self.renewed >= self.sessions_funded() {
            return Err(SesError::Exhausted);
        }
        self.renewed = self.renewed.checked_add(1).ok_or(SesError::Exhausted)?;
        Ok(())
    }

    /// How many sessions have been renewed (spent into).
    #[must_use]
    pub fn renewed_count(&self) -> u64 {
        self.renewed
    }

    /// Whether the member is revoked: it has not renewed (spent into the next session)
    /// for every elapsed session by the deadline (REQ-SES-010 revocation-by-non-spend).
    #[must_use]
    pub fn is_revoked(&self, sessions_elapsed: u64) -> bool {
        self.renewed < sessions_elapsed
    }

    /// The subscription mode.
    #[must_use]
    pub fn mode(&self) -> SubscriptionMode {
        self.mode
    }
}

/// A sub-session: a session nested under a parent session, identified by the parent's
/// transaction id (display hex). It carries its own eligible-member set and rekeying.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubSession {
    /// The parent session transaction id (display hex).
    pub parent_txid: String,
    /// The sub-session index under the parent.
    pub index: u32,
}

impl SubSession {
    /// Create a sub-session under a parent session transaction.
    #[must_use]
    pub fn new(parent_txid: String, index: u32) -> Self {
        Self { parent_txid, index }
    }
}
