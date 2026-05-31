# Security model and honest labelling

What the system secures, and what it does not — stated honestly (REQ terminology
honesty). Detail per crate is added as each crate is built.

## Trust root

All chain-terminating verification ends in `bsv::HeaderChain` (REQ-BSV-041/042):
prev-hash linkage, proof-of-work against the encoded target, monotonic height. A
result is accepted only if its root is the merkle root of a header in a validated
header chain. Node responses are untrusted and validated against this root.

## Secret hygiene

Seeds, chain codes, symmetric keys, key-shares, and plaintext-before-encryption are
held in `secmem::Secret`/`SecretBytes`: zeroize-on-drop, redacted `Debug`, no
`Serialize`, constant-time equality, best-effort memory locking. No secret appears in
any error, log, or audit record.

## What each mechanism conceals (no over-claiming)

- **Obfuscation keys (EP cl.5a):** strength is exactly AES-256-GCM under the derived
  key — no property is claimed beyond the cipher (REQ-OVL-022).
- **Position-only signalling (EP):** transmitting a node position reveals only the
  position; without the relevant seed the receiver cannot perform the seed-isolated
  function (e.g. cannot de-obfuscate). Held under hardened CKD so leakage of a derived
  writing key recovers neither parent, sibling, nor the second seed (REQ-CKD-004,
  REQ-OVL-052).
- **Broadcast key graph (GB):** an eligible user decrypts up the graph to the message
  key; a non-eligible user cannot. Key-wrap is authenticated AEAD, never raw XOR.

## Custody boundary (to finalise at step 10)

True threshold signing never reassembles the private key. The Shamir-reconstruction
mode is a separate, clearly-labelled fallback that transiently reconstructs a quorum,
signs, and provably discards the key. The boundary is documented where used.

## Out of scope

The system secures existence, integrity, identity, authorisation, and confidentiality
of the on-chain/key-graph artifacts. It does not secure application semantics above
the obfuscation layer beyond the cipher's guarantee.
