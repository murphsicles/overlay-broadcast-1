# ckd — child key derivation specification (REQ-CKD-001)

The exact, auditable construction. BIP32-style hierarchical deterministic derivation
using HMAC-SHA512 over secp256k1.

## Master key

```
I        = HMAC-SHA512(key = "Bitcoin seed", data = seed)      // 64 bytes
IL       = I[0..32]                                            // master private key
IR       = I[32..64]                                           // master chain code
require 0 < parse256(IL) < n                                   // else the seed is invalid
```

`parse256` interprets 32 bytes as a big-endian integer; `n` is the secp256k1 group
order. The seed length must be 16–64 bytes.

## Child derivation, private parent → private child (CKDpriv)

```
if hardened (index >= 2^31):
    data = 0x00 || ser256(k_par) || ser32(index)
else:
    data = serP(point(k_par)) || ser32(index)
I    = HMAC-SHA512(key = c_par, data)
IL   = I[0..32];  IR = I[32..64]
require parse256(IL) < n                                       // else advance index
k_i  = (parse256(IL) + k_par) mod n
require k_i != 0                                               // else advance index
c_i  = IR
```

- `ser32(i)` = the 4-byte big-endian encoding of `i`.
- `ser256(k)` = the 32-byte big-endian encoding of a scalar.
- `serP(P)` = the 33-byte compressed SEC1 encoding of a point.
- `point(k)` = `k · G`.
- the hardened bit is `index >= 2^31` (`0x8000_0000`).

## Child derivation, public parent → public child (CKDpub)

Non-hardened only:

```
data = serP(K_par) || ser32(index)
I    = HMAC-SHA512(key = c_par, data)
K_i  = point(parse256(IL)) + K_par
c_i  = IR
```

`CKDpub(index)` is undefined for hardened indices and is refused.

## Determinism

For a fixed `(seed, path)`, every derived key is identical across runs, processes,
and platforms (REQ-CKD-002), because every step is a deterministic function of public
constants and the seed.

## Conformance

Validated against published BIP32 test vector 1 (`crates/ckd/tests/bip32_vectors.rs`):
the master triple in full, and the `m/0H/1` public key reproduced through a
hardened-then-non-hardened derivation.
