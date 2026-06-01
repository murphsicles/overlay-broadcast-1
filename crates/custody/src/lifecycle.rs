//! Key custody lifecycle (REQ-CUS-006/007): a tamper-evident, hash-chained log of key
//! genesis, rotation, and revocation events. Each event commits to its predecessor's
//! hash via `double_sha256`, so the head hash is a single value that can be anchored on
//! chain (in an overlay OP_RETURN) to make the whole history publicly auditable. A
//! revoked key chain refuses further rotation.
use crate::error::CustodyError;
use bsv::{double_sha256, Hash256};

/// The kind of a lifecycle event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// The first event: the key is established.
    Genesis,
    /// The key is rotated to a new public key.
    Rotation,
    /// The key is revoked; no further rotation is permitted.
    Revocation,
}

impl EventKind {
    const fn tag(self) -> u8 {
        match self {
            EventKind::Genesis => 0,
            EventKind::Rotation => 1,
            EventKind::Revocation => 2,
        }
    }
}

/// One link in the custody hash chain.
#[derive(Clone, Debug)]
pub struct LifecycleEvent {
    /// What happened.
    pub kind: EventKind,
    /// The compressed public key in effect after this event.
    pub public_key: [u8; 33],
    /// A monotonic logical time (e.g. block height or sequence number).
    pub logical_time: u64,
    /// The hash of the previous event (genesis links to all-zero).
    pub prev_hash: Hash256,
    /// This event's hash.
    pub hash: Hash256,
}

fn event_hash(
    kind: EventKind,
    public_key: &[u8; 33],
    logical_time: u64,
    prev: &Hash256,
) -> Hash256 {
    let mut buf = Vec::with_capacity(1 + 33 + 8 + 32);
    buf.push(kind.tag());
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(&logical_time.to_be_bytes());
    buf.extend_from_slice(prev.internal());
    double_sha256(&buf)
}

/// A custodian tracking one key's lifecycle as an anchorable hash chain.
#[derive(Clone, Debug)]
pub struct KeyCustodian {
    public_key: [u8; 33],
    revoked: bool,
    events: Vec<LifecycleEvent>,
}

impl KeyCustodian {
    /// Establish a new key chain with its genesis event.
    #[must_use]
    pub fn new(public_key: [u8; 33], logical_time: u64) -> Self {
        let prev_hash = Hash256::from_internal([0u8; 32]);
        let hash = event_hash(EventKind::Genesis, &public_key, logical_time, &prev_hash);
        let genesis = LifecycleEvent {
            kind: EventKind::Genesis,
            public_key,
            logical_time,
            prev_hash,
            hash,
        };
        Self {
            public_key,
            revoked: false,
            events: vec![genesis],
        }
    }

    /// Whether the key has been revoked.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    /// The current public key.
    #[must_use]
    pub fn current_key(&self) -> [u8; 33] {
        self.public_key
    }

    /// The head hash of the chain — the value to anchor on chain.
    #[must_use]
    pub fn head_hash(&self) -> Hash256 {
        match self.events.last() {
            Some(event) => event.hash,
            None => Hash256::from_internal([0u8; 32]),
        }
    }

    /// The full event log.
    #[must_use]
    pub fn events(&self) -> &[LifecycleEvent] {
        &self.events
    }

    /// Rotate to a new public key.
    ///
    /// # Errors
    /// [`CustodyError::Revoked`] if the key is already revoked.
    pub fn rotate(
        &mut self,
        new_public_key: [u8; 33],
        logical_time: u64,
    ) -> Result<(), CustodyError> {
        if self.revoked {
            return Err(CustodyError::Revoked);
        }
        let prev_hash = self.head_hash();
        let hash = event_hash(
            EventKind::Rotation,
            &new_public_key,
            logical_time,
            &prev_hash,
        );
        self.events.push(LifecycleEvent {
            kind: EventKind::Rotation,
            public_key: new_public_key,
            logical_time,
            prev_hash,
            hash,
        });
        self.public_key = new_public_key;
        Ok(())
    }

    /// Revoke the key. Idempotent only insofar as a second call appends another
    /// revocation event; after the first the key is permanently revoked.
    ///
    /// # Errors
    /// [`CustodyError::Revoked`] if already revoked.
    pub fn revoke(&mut self, logical_time: u64) -> Result<(), CustodyError> {
        if self.revoked {
            return Err(CustodyError::Revoked);
        }
        let prev_hash = self.head_hash();
        let hash = event_hash(
            EventKind::Revocation,
            &self.public_key,
            logical_time,
            &prev_hash,
        );
        self.events.push(LifecycleEvent {
            kind: EventKind::Revocation,
            public_key: self.public_key,
            logical_time,
            prev_hash,
            hash,
        });
        self.revoked = true;
        Ok(())
    }
}

/// Verify a lifecycle log: genesis first, each event re-hashing to its stored hash,
/// each `prev_hash` matching the predecessor, time non-decreasing, and at most one
/// terminal revocation.
#[must_use]
pub fn verify_lifecycle(events: &[LifecycleEvent]) -> bool {
    let Some(first) = events.first() else {
        return false;
    };
    if first.kind != EventKind::Genesis || first.prev_hash != Hash256::from_internal([0u8; 32]) {
        return false;
    }
    let mut last_time = 0u64;
    let mut seen_revocation = false;
    for (position, event) in events.iter().enumerate() {
        if seen_revocation {
            return false;
        }
        if position == 0 {
            if event.kind != EventKind::Genesis {
                return false;
            }
        } else if event.kind == EventKind::Genesis {
            return false;
        }
        let expected = event_hash(
            event.kind,
            &event.public_key,
            event.logical_time,
            &event.prev_hash,
        );
        if expected != event.hash {
            return false;
        }
        if position > 0 {
            match events.get(position - 1) {
                Some(previous) if previous.hash == event.prev_hash => {}
                _ => return false,
            }
        }
        if event.logical_time < last_time {
            return false;
        }
        last_time = event.logical_time;
        if event.kind == EventKind::Revocation {
            seen_revocation = true;
        }
    }
    true
}
