# ckd — security analysis (REQ-CKD-003/004/009)

## Hardened vs non-hardened: the central boundary (REQ-CKD-003)

Both modes are supported. Their security difference is the crux of the EP
position-signalling scheme.

**Non-hardened derivation failure mode.** Exposure of ONE child PRIVATE key together
with the parent PUBLIC key and the parent chain code permits recovery of the parent
PRIVATE key, and therefore of every sibling:

```
non-hardened:  k_child = (IL + k_parent) mod n
               IL      = HMAC-SHA512(c_parent, serP(K_parent) || ser32(index))[0..32]
```

`IL` is a function of PUBLIC data only (`K_parent`, `c_parent`, `index`). An attacker
who learns `k_child` computes `IL` from the public data and recovers
`k_parent = (k_child − IL) mod n`. With `k_parent` and `c_parent` every sibling is
derivable. This is demonstrated as a positive recovery in
`tests/seed_isolation.rs::seed_isolation_under_key_leakage`.

**Hardened derivation defeats this.** For a hardened index,

```
hardened:      IL = HMAC-SHA512(c_parent, 0x00 || ser256(k_parent) || ser32(index))[0..32]
```

`IL` now depends on the SECRET `k_parent`. An attacker with only `k_child`, `K_parent`,
and `c_parent` cannot compute `IL`, so cannot recover `k_parent` or any sibling. The
same test asserts this recovery FAILS for the hardened child.

## RULE: writing-key derivation is hardened (REQ-CKD-004)

The EP first/writing key set used in position-only signalling
(`Seeds::writing_key` → `Position::hardened_path`) is derived with HARDENED indices.
A derived writing key may be shared/leaked while parent public material is known to
the receiver; hardened derivation guarantees that such leakage recovers neither the
parent nor a sibling writing key. Non-hardened derivation is used ONLY for key sets
that carry no co-located private/public hazard (e.g. public-derivable function keys
where no child private key co-exists with shared parent public material).

## Seed isolation (REQ-CKD-005/006)

The first/second/third seeds are independent derivation domains held as zeroizing
`SecretBytes`. They are derived from a single master seed by domain-separated
HMAC-SHA512 (`HMAC-SHA512(master, "overlay-broadcast/seed/<role>/v1")[0..32]`), and
are also independently importable. The same path under different seeds yields
independent keys with no derivable relation (`tests/seed_isolation.rs`).

## Constant-time scalar arithmetic (REQ-CKD-009)

All scalar arithmetic is performed by the pinned `k256` crate (RustCrypto,
NCC-audited), whose field and scalar operations are constant-time; there is no
secret-dependent branch or table index in this crate's derivation code. The derivation
inputs (private key, chain code) are handled as `SecretBytes` and parsed into k256
scalars whose operations carry the crate's constant-time guarantee.
