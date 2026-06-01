# Hardened multi-stage build (REQ-CON-001/002). The runtime stage is distroless: no
# shell, no package manager, no build toolchain; non-root UID; the rootfs is mounted
# read-only at runtime (compose/k8s) and the binary needs no write access. Secrets are
# injected at runtime (env / tmpfs), never baked into a layer.
FROM rust:1.96.0-slim AS build
ENV CARGO_HTTP_CHECK_REVOKE=false
WORKDIR /src
COPY . .
# The CLI (selftest/reproduce/operations) and the served HTTP api server.
RUN cargo build --release --bin overlay-broadcast --bin overlay-broadcast-server

# Minimal, non-root runtime. `:nonroot` runs as UID 65532 with no shell.
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
WORKDIR /app
COPY --from=build /src/target/release/overlay-broadcast /app/overlay-broadcast
COPY --from=build /src/target/release/overlay-broadcast-server /app/overlay-broadcast-server
USER nonroot:nonroot
EXPOSE 8080
# Liveness via the CLI selftest (the served /health + /readiness endpoints are the api's
# own liveness/readiness once the server is the entrypoint).
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/app/overlay-broadcast", "selftest"]
# Default to the CLI; deployments override the entrypoint to run the server, e.g.
# `docker run ... overlay-broadcast:enterprise` -> selftest, or set the server entrypoint
# in compose/k8s (see docker-compose.hardened.yml).
ENTRYPOINT ["/app/overlay-broadcast"]
CMD ["selftest"]
