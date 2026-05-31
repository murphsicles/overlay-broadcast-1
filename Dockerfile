# Hardened multi-stage build (REQ-CON-010..013). Pinned base by digest is applied
# when the supply-chain hardening step lands; the skeleton establishes the
# distroless, non-root, read-only-rootfs shape now.
FROM rust:1.96.0-slim AS build
ENV CARGO_HTTP_CHECK_REVOKE=false
WORKDIR /src
COPY . .
RUN cargo build --release --bin cli || cargo build --release

# Minimal, non-root runtime.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
WORKDIR /app
# The cli binary is copied here once the cli crate (step 15) exists.
# COPY --from=build /src/target/release/cli /app/cli
USER nonroot:nonroot
ENTRYPOINT ["/app/cli"]
