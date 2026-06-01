# Architecture

BSV-native Rust implementation of EP 4 046 048 B1 (overlay key-graph + seed-isolated
position signalling) and GB 2623780 B (key-graph broadcast encryption + session
lifecycle), graded to NPR 7150.2 / JPL Power-of-Ten / MC-DC.

## Layering and trust root

A Cargo workspace of layered crates; lower crates never depend on upper crates
(REQ-GOV-002). The single root of trust is the BSV block-header chain
(`bsv::HeaderChain`, REQ-BSV-041/042): no chain-terminating verification anywhere
accepts a result unless its root is the merkle root of a header in a validated
header chain (prev-hash linkage + proof-of-work + monotonic height).

```
secmem  -> bsv -> ckd -> cipher -> keygraph -> overlay   (EP)
                                             -> broadcast (GB) -> session
                  custody   kst   obs   api   cli   bench
```

Build order is Section 23 of the SRS; each step's full CI gate is green before the
next (REQ-BLD-001).

## Pinned dependencies (REQ-UNI-006/007, REQ-CKD-010, REQ-CUS-002/010, REQ-KST-010/011)

| concern | pin | rationale |
| --- | --- | --- |
| toolchain | Rust 1.96.0, components rustfmt/clippy/llvm-tools-preview | reproducible build (REQ-GOV-001) |
| secp256k1 | `k256` (RustCrypto), `default-features = false`, features `ecdsa`+`arithmetic`+`std` | pure-Rust (no C toolchain), NCC-audited; provides low-S normalization and RFC-6979 deterministic signing, both **proven by test** (REQ-BSV-032, REQ-CKD-010) rather than assumed; `Scalar` implements `Zeroize` (via the non-optional `elliptic-curve` zeroize dep), so reconstruction-mode custody wipes the transiently-recovered key (REQ-CUS-004) |
| hashing | `sha2`, `ripemd`, `hmac`, `hkdf` (RustCrypto) | KAT-verified; double-SHA-256, hash160, HMAC-SHA512 (CKD), HKDF-SHA256 (ECIES) |
| AEAD | `aes-gcm` (RustCrypto) | AES-256-GCM with enforced nonce-uniqueness invariant (REQ-CIPH-010) |
| secret hygiene | `zeroize`, `subtle` | zeroize-on-drop, constant-time equality (Section 3) |

### BSV SDK (REQ-UNI-006/007)

There is no established, audited Rust crate equivalent to a full "BSV SDK". Per
**REQ-UNI-007** ("where the pinned SDK does not provide a required property, the
build SHALL supply it at the project wrapper layer and SHALL NOT assume the SDK
provides it"), the `bsv` crate supplies BSV primitives — Hash256/byte-order,
txid, transaction parse/serialise, post-Genesis script, FORKID sighash, header
chain, data carrier — at the wrapper layer over the vetted RustCrypto hashing
crates and `k256` for curve/ECDSA. Every chain-facing property (low-S, RFC-6979,
sighash KATs, header-chain validation) is verified by test against genuine BSV
fixtures, never assumed. If a maintained, audited BSV SDK crate is later pinned,
the wrapper traits are the seam to adopt it behind.

### Threshold scheme (REQ-CUS-002) — ratify at step 10

The custody crate's *true threshold* (key never reconstructed) is pinned to
**FROST over secp256k1** (Chu–Komlo–Goldberg–et al.; "FROST: Flexible Round-Optimized
Schnorr Threshold Signatures", 2020), a published, peer-reviewed construction. Note
the consequence to ratify: FROST produces **Schnorr** group signatures, whereas a
BSV transaction input requires **ECDSA**. Therefore on-chain broadcaster ECDSA
signatures use the **Shamir-reconstruction custody** mode (REQ-CUS-005; reconstructs
a quorum, signs, provably discards the key) where a single valid BSV ECDSA signature
is required, while FROST provides true-threshold authority signatures off the input
path. The alternative — GG20 threshold ECDSA (Gennaro–Goldfeder, 2020) — yields
on-chain-valid ECDSA but has a thinner audited-Rust surface. This fork is flagged
for explicit ratification when custody is built.

**Ratified at step 10 (2026-05):** built as pinned — FROST true-threshold Schnorr
(committed nonces, Lagrange on partial signatures; key never reconstructed) for
authority signatures, plus Shamir-reconstruction mode for the single on-chain ECDSA
signature path (transient reconstruction, key wiped via `Scalar`/byte zeroize). GG20
remains the documented upgrade if a future requirement needs true-threshold *ECDSA*
on the input path; revisit when an audited GG20 Rust crate is available.

### KeyStore backends (REQ-KST-010/011)

PKCS#11 HSM via `cryptoki`; cloud KMS via a pinned KMS client (envelope
encryption). Both are integration-tested `#[ignore]` without the hardware/service,
each naming the exact backend required (REQ-TST-050).

## Build-environment note (REQ-GOV-001 reproducibility)

`.cargo/config.toml` sets `http.check-revoke = false`. The build host cannot reach
the CA CRL/OCSP endpoints, so schannel otherwise fails the TLS handshake to
crates.io with `CRYPT_E_NO_REVOCATION_CHECK`. The certificate is still validated;
only the online revocation check is skipped. This is recorded here as required.

## Licensing vs patents

The source is dual-licensed MIT OR Apache-2.0. This is the **code** license and is
independent of the patent rights in EP 4 046 048 B1 and GB 2623780 B; implementing a
patented method under an open code license grants no patent license.
