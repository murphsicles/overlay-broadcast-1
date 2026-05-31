# Coding standard (Power-of-Ten, Rust adaptation) — REQ-GOV-040..049

Enforceable restatement of REQ-GOV-010..020. Each rule names its enforcement
mechanism. CI runs `cargo clippy --all-targets --all-features -- -D warnings`, so
every lint below is `deny` (a `warn` would fail the gate anyway).

## Rules

1. **Restrict `unsafe` (REQ-GOV-010).** Every crate declares `#![forbid(unsafe_code)]`
   at crate root, EXCEPT the audited `secmem` crate, which declares
   `#![deny(unsafe_code)]` with each `unsafe` block carrying a `// SAFETY:` comment,
   isolated to one module. Enforcement: crate-root attributes + the `xtask` source
   scan + review.

2. **No panicking constructs in non-test code (REQ-GOV-011).** Denied clippy lints:
   `unwrap_used`, `expect_used`, `panic`, `unreachable`, `todo`, `unimplemented`,
   `panic_in_result_fn`. Use `Result`, `?`, and explicit handled paths. Test code may
   use `unwrap`/`expect`/`assert` under a `#[cfg(test)]` `#[allow(...)]`.

3. **No out-of-bounds and no truncating casts (REQ-GOV-011).** Denied:
   `indexing_slicing` (use `.get()` / iterators), `as_conversions`,
   `cast_possible_truncation`, `cast_possible_wrap`, `cast_sign_loss` (use
   `TryFrom`/`TryInto`). Integer overflow is caught at runtime by
   `overflow-checks = true` in every profile.

4. **Bounded loops over external input (REQ-GOV-013).** Every loop consuming external
   input has a statically evident or explicitly enforced upper bound. Enforcement:
   analysis + resource-exhaustion tests.

5. **Bounded allocation in hot paths (REQ-GOV-014).** No unbounded growth keyed on
   external input; soak tests assert no unbounded growth.

6. **Function size (REQ-GOV-015).** No public function exceeds 60 executable lines.
   Enforcement: `cargo run -p xtask -- fn-size`.

7. **Assertion density (REQ-GOV-016).** Crypto/protocol crates average ≥ 2 invariant
   checks per non-trivial function (`debug_assert!` + a handled error path; never a
   bare `panic!` on external input in release).

8. **Smallest scope; no ad-hoc mutable global state (REQ-GOV-017).**

9. **Use every return value (REQ-GOV-018).** `#[must_use]` on fallible/important
   returns; `let _ =` only with a justifying comment.

10. **Restrained macros, no raw pointers in safe code (REQ-GOV-019/020).**

11. **Zero warnings at maximum strictness (REQ-GOV-031).** `cargo build` and
    `cargo clippy --all-targets --all-features` run with `-D warnings`; rustc lints
    `unused`, `future_incompatible`, `rust_2021_compatibility` are denied.

## Compliant vs non-compliant examples

```rust
// NON-COMPLIANT: panics, indexes, truncates.
fn bad(buf: &[u8]) -> u16 { (buf[0] as u16) << 8 | buf[1] as u16 }

// COMPLIANT: checked access, fallible, no cast panic.
fn good(buf: &[u8]) -> Result<u16, ParseError> {
    let hi = u16::from(*buf.first().ok_or(ParseError::Short)?);
    let lo = u16::from(*buf.get(1).ok_or(ParseError::Short)?);
    Ok(hi.checked_shl(8).ok_or(ParseError::Overflow)? | lo)
}
```
