# overlay-broadcast

A BSV-native Rust implementation of two inventions, graded to NPR 7150.2 / JPL
Power-of-Ten / MC-DC coverage with a full requirements-traceability matrix:

- **EP 4 046 048 B1** — an overlay key-graph over data-storage transactions, with
  first/second/third function key sets, the three claim-5 functions, and seed-isolated
  position-only signalling.
- **GB 2623780 B** — key-graph broadcast encryption, three rekeying strategies, and the
  on-chain session lifecycle.

BSV is the entire technical universe: post-Genesis protocol only, secp256k1
throughout, on-chain value named exclusively in **minor units**. Verification
terminates in the validated BSV block-header chain (the trust root).

## Build and gate

```
cargo build --release
cargo test --all
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo run -p xtask -- all      # banned-token, function-size, and RTM gates
```

The build environment sets `http.check-revoke = false` in `.cargo/config.toml` (the
sandbox cannot reach the CA revocation endpoints); see docs/ARCHITECTURE.md.

## Crates (built in the Section 23 order)

`secmem` (audited secret containers) · `bsv` (primitives + header-chain trust root) ·
`ckd` (child key derivation, EP) · `cipher` (AEAD, ECIES, key-wrap) · `keygraph` ·
`overlay` (EP) · `broadcast` (GB) · `session` (GB lifecycle) · `custody` (threshold +
reconstruction) · `kst` (KeyStore: HSM/KMS/file) · `obs` · `api` · `cli` · `bench`.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — layering, trust root, pinned deps.
- [docs/CODING_STANDARD.md](docs/CODING_STANDARD.md) — the Power-of-Ten Rust rules.
- [docs/SECURITY.md](docs/SECURITY.md) — what each mechanism conceals (honest labelling).
- [docs/RTM.csv](docs/RTM.csv) — requirements-to-test traceability matrix.

The source is dual-licensed MIT OR Apache-2.0; this code license is independent of the
patent rights in the two inventions.
