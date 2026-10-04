# syntax=docker/dockerfile:1

# Build a static binary (SQLite is pure Go, so no CGO is needed). The build
# stage runs on the build machine's platform and cross-compiles, so
# multi-architecture images build without emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/siemlite . && mkdir -p /out/data

# Minimal runtime: no shell or package manager, runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/justwaters/SIEMLite" \
      org.opencontainers.image.description="A SIEM in a single Go binary" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --from=build /out/siemlite /usr/local/bin/siemlite
# A new named volume copies this directory's ownership, so nonroot can write it.
COPY --from=build --chown=nonroot:nonroot /out/data /data
# The database and TLS certificate live here; management commands such as
# `siemlite users list` find them through the default relative paths.
WORKDIR /data
VOLUME /data
USER nonroot
# HTTPS, then syslog on unprivileged ports (compose maps 514 to 5514).
EXPOSE 8443 5514/tcp 5514/udp 6514
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["siemlite", "healthcheck"]
ENTRYPOINT ["siemlite"]
CMD ["-addr", "0.0.0.0:8443"]
