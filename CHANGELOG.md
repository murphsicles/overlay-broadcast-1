# Changelog

Semantic versioning (REQ-GOV-080). Keep-a-changelog format.

## [Unreleased]

### Added
- Step 1 (REQ-BLD-001.1): Cargo workspace skeleton; pinned toolchain
  (rust-toolchain.toml, Rust 1.96.0 + rustfmt/clippy/llvm-tools); workspace lint
  policy enforcing the Power-of-Ten clippy set with `-D warnings` and
  `overflow-checks = true` in every profile; `.cargo/config.toml`; the `xtask` gate
  crate (banned-token gate REQ-UNI-005/GOV-071, function-size gate REQ-GOV-015, RTM
  structural gate REQ-GOV-060/061) with unit tests; `deny.toml`; CI workflow
  (REQ-GOV-032); hardened Dockerfile + compose skeleton (REQ-CON); docs skeleton
  (ARCHITECTURE with pins, CODING_STANDARD, SECURITY); `docs/RTM.csv` skeleton;
  `legacy/` preservation note (REQ-GOV-070).
