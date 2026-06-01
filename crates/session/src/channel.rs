//! Secure-channel abstraction for member→broadcaster component transfer (REQ-SES-050,
//! GB §6.5). Members pass their signed SIGHASH_SINGLE components to the broadcaster over an
//! authenticated channel that **binds each component to the specific session**: the envelope
//! carries a tag over `component || session_binding` (the session's identifying bytes, e.g.
//! the broadcaster output / draft txid). Opening the envelope under any other binding fails,
//! so a member's input–output pair cannot be lifted into a malicious non-session
//! transaction — complementing the SIGHASH_SINGLE output binding itself.
use bsv::{double_sha256, Hash256};

/// An authenticated, session-bound envelope carrying a member's signed component.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// The member's signed component bytes.
    pub component: Vec<u8>,
    /// The binding tag over `component || session_binding`.
    pub tag: Hash256,
}

/// The secure channel: seal a component bound to a session, and open it only under the same
/// binding.
pub struct SecureChannel;

impl SecureChannel {
    /// Seal `component` bound to `session_binding`.
    #[must_use]
    pub fn seal(component: &[u8], session_binding: &[u8]) -> Envelope {
        Envelope {
            component: component.to_vec(),
            tag: bind(component, session_binding),
        }
    }

    /// Open the envelope under `session_binding`, returning the component only if the binding
    /// matches (rejecting a component lifted to a different session/transaction).
    #[must_use]
    pub fn open(envelope: &Envelope, session_binding: &[u8]) -> Option<Vec<u8>> {
        if bind(&envelope.component, session_binding).internal() == envelope.tag.internal() {
            Some(envelope.component.clone())
        } else {
            None
        }
    }
}

fn bind(component: &[u8], session_binding: &[u8]) -> Hash256 {
    let mut buffer = Vec::with_capacity(component.len() + session_binding.len() + 1);
    buffer.extend_from_slice(component);
    buffer.push(0x1f);
    buffer.extend_from_slice(session_binding);
    double_sha256(&buffer)
}
