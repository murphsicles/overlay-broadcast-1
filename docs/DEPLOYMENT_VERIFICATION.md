# Enterprise deployment verification (2026-06)

The hardened container and the genuine-node conformance were built and **executed** on a
Linux Docker engine (Docker 29.5.2, in WSL2 Ubuntu 24.04) — not just authored.

## Hardened runtime image (REQ-CON-001/002)

`docker build -t overlay-broadcast:enterprise .` → **39.4 MB** distroless image. Verified:

| Check | Result |
| --- | --- |
| `selftest` under `--read-only --cap-drop ALL --security-opt no-new-privileges` | all 12 layers pass, exit 0 |
| Configured user | `nonroot:nonroot` (UID 65532) — non-root |
| Shell present in runtime image | **none** — `/bin/sh` absent (distroless) |
| Healthcheck | `["CMD", "/app/overlay-broadcast", "selftest"]` |
| `reproduce` in-container | deterministic vectors regenerated (`sha256(abc)=ba7816bf…015ad`) |

## In-container full test profile (REQ-CON-011)

`docker compose -f docker-compose.hardened.yml run --rm --build test` runs the complete
suite in-container: **`cargo test --all` (0 failures)**, **`cargo run -p xtask -- all`**
(banned-tokens, fn-size, RTM, SBOM — **192-component CycloneDX SBOM generated**),
**`reproduce`**, and **`selftest` (12/12)**. All green. (Note: `xtask` runs cleanly in the
Linux container; its occasional hang is a Windows-only AV/process artifact.)

## Genuine Teranode acceptance (REQ-TST-012, "Teranode where configured")

Validated against a **live Teranode v0.15.1 regtest node** (`getbestblockhash` /
`getblockheader … false` over the JSON-RPC at `127.0.0.1:9292`). Our independent
`bsv::BlockHeader::parse` + double-SHA-256 `block_hash()` reproduced the node's reported
block hash exactly, and the header re-serialized byte-identically:

```
node best block hash : 607c10f0cacc6b8fa3e850f4bf30834a77526e6193a5373c31d6fcac74edf9c6
our recomputed hash  : 607c10f0cacc6b8fa3e850f4bf30834a77526e6193a5373c31d6fcac74edf9c6   ✓
```

Reproduce with:

```
TERANODE_HEADER_HEX=<getblockheader hex>  TERANODE_BLOCK_HASH=<getbestblockhash> \
  cargo test -p conformance tst_tst_012_teranode_genuine_header -- --ignored
```

This closes the external genuine-data acceptance with a real node, complementing the
in-process independent-path conformance (`tst_tst_012_ep_overlay_transaction`,
`tst_tst_012_gb_session_transaction`, `tst_tst_012_signature_validates_independently`).
