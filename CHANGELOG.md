# Changelog

Semantic versioning (REQ-GOV-080). Keep-a-changelog format.

## [Unreleased]

## [0.2.1] - 2026-06

### Verified
- Enterprise Docker proven end-to-end on a real Linux engine (`docs/DEPLOYMENT_VERIFICATION.md`):
  hardened 39.4 MB distroless image (non-root, read-only rootfs, all caps dropped, no shell,
  healthcheck) with `selftest`/`reproduce` passing; the in-container `test` profile runs the
  full suite + `xtask all` (192-component SBOM) + reproduce + selftest, all green
  (REQ-CON-001/002/011).
- External genuine-data conformance against a **live Teranode v0.15.1 node** (REQ-TST-012):
  our `bsv` header parser + double-SHA-256 reproduce the node's reported block hash exactly
  (`tst_tst_012_teranode_genuine_header`).

## [0.2.0] - 2026-06

### Added
- Adversarial threat-model suite (`sec` crate, Section 16): one executable test per
  threat (REQ-SEC-001..009, 031, 100) that mounts the attack and asserts the mitigation
  defeats it — SIGHASH_SINGLE lift, the "1" hash bug, broadcaster equivocation, replay,
  griefing, seed-isolation breach (negative), revoked re-spend, high-S malleability, api
  auth replay/forgery, secret leakage, resource exhaustion.
- Session lifecycle completion (REQ-SES-011/020/030/040/050): on-block funding +
  pair-signing, revocation, sub-session split, upload-gated release + re-encrypt, and a
  `SecureChannel` abstraction that binds a member's component to its session (lift
  prevention).
- Full requirements-traceability reconciliation: every spec requirement (incl. SEC, the
  remaining SES, GOV inspection items, UNI, and the build-order meta-requirements) is now
  mapped in `docs/RTM.csv`.

## [0.1.4] - 2026-06

### Added
- GG20 type-7 fault attribution (`custody::type7`): a proof-valid run that still yields an
  invalid signature is pinpointed to the party whose final share fails
  `s_i·G == m·K_i + r·Σ_i`. Completes the GG20 identifiable-abort surface.

## [0.1.3] - 2026-06

### Added
- GG20 identifiable abort: `gg20::sign_identifiable` attributes a bad modulus/range/
  responder proof to the exact party (`AbortError`), and the echo-broadcast round
  (`custody::echo`) localizes equivocation.

## [0.1.2] - 2026-06

### Added
- GG20 responder consistency proof Π′ and Paillier-modulus proof Π_N, verified inside
  every MtA.

## [0.1.1] - 2026-06

### Added
- GG20 MtA initiator range proof Π (`custody::rangeproof`), verified inside every MtA.

## [0.1.0] - 2026-06

### Added
- Complete 21-step build (Section 23): `secmem`, `bsv`, `ckd`, `cipher`, `keygraph`,
  `overlay` (EP 4 046 048 B1), `broadcast` (GB 2623780 B), `session`, `custody`
  (FROST + hand-rolled GG20 threshold ECDSA + Shamir reconstruction), `kst`, `obs`,
  `api`, `res`, `cli`, `cmp`, `bench`, plus `proptests`, `conformance`, and fuzzing
  (libFuzzer targets + a stable robustness fuzzer). Both inventions implemented in full;
  `cargo test --all` green; clippy/fmt/`cargo doc -D warnings` clean; CycloneDX SBOM,
  cargo-deny/audit, coverage/mutation, reproduce, and selftest gates wired into CI.
- Step 1: Cargo workspace skeleton; pinned toolchain (rust-toolchain.toml, Rust 1.96.0);
  Power-of-Ten clippy lint policy with `-D warnings`; `xtask` gate crate (banned-token,
  function-size, RTM, SBOM); `deny.toml`; CI workflow; hardened Dockerfile + compose;
  docs + `docs/RTM.csv` skeletons; `legacy/` preservation (REQ-GOV-070).
