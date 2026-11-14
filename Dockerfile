# syntax=docker/dockerfile:1.10
# nrzDNS – Multi-Stage-Build für amd64 und arm64: Oberfläche (Dioxus/WebAssembly), DNS-Engine
# und Server (Rust) in einer Datei. Braucht nur Docker – kein Rust auf dem Rechner.
#   docker build -t nrzdns .
#   docker run -p 53:53/udp -p 53:53/tcp -p 8380:8380 -p 80:80 -v nrzdns-data:/data nrzdns
# Beide Architekturen (Rust wird quer-kompiliert, nicht emuliert):
#   docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/nrz-dns:<version> --push .
# Nur das Programm für beide Architekturen (landet in dist/linux_<arch>/nrzdns):
#   docker buildx build --platform linux/amd64,linux/arm64 --target binaries --output type=local,dest=dist .
# Fürs Umbrel-Paket (gzip, nrzdns-amd64.gz / nrzdns-arm64.gz): scripts/store-binaries.sh <ordner>

# Dasselbe gepinnte Debian wie die Umbrel-App (Multi-Arch-Manifest).
ARG DEBIAN=debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

# Gebaut wird auf bookworm (glibc 2.36): das Programm läuft damit auch auf älteren Systemen.
ARG RUST=rust:1.98-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e

# ---------------------------------------------------------------- Oberfläche
# WebAssembly ist überall gleich – einmal auf dem Build-Rechner bauen, für alle Architekturen.
FROM --platform=$BUILDPLATFORM ${RUST} AS ui
RUN rustup target add wasm32-unknown-unknown
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo install dioxus-cli --version 0.7.10 --locked --root /opt/dx
WORKDIR /src
# Die Oberfläche benutzt die Typen der JSON-API aus types/ (Pfad-Abhängigkeit ../types).
COPY types types
COPY ui ui
# `dx bundle` räumt seinen Zwischenordner nicht auf – vorher leeren, sonst landen alte
# WASM-Dateien aus dem Cache mit im Programm.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/ui/target,id=nrzdns-ui-target \
    cd ui && rm -rf target/dx/*/release/web/public \
 && PATH=/opt/dx/bin:$PATH dx bundle --web --release --out-dir /tmp/ui \
 && mkdir -p /out && cp -r /tmp/ui/public /out/public && test -f /out/public/index.html

# ---------------------------------------------------------------- Programm
FROM --platform=$BUILDPLATFORM ${RUST} AS build
ARG TARGETARCH
ARG BUILDARCH
# Querübersetzer, wenn Ziel und Build-Rechner verschieden sind (das gebündelte SQLite und
# ring werden mit dem C-Compiler des Ziels gebaut).
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) t=x86_64-unknown-linux-gnu; p=x86_64-linux-gnu; pkg="gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
      arm64) t=aarch64-unknown-linux-gnu; p=aarch64-linux-gnu; pkg="gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
      *) echo "Architektur $TARGETARCH nicht unterstützt" >&2; exit 1 ;; \
    esac; \
    echo "$t" > /rust-target; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update && apt-get install -y --no-install-recommends $pkg && rm -rf /var/lib/apt/lists/*; \
      rustup target add "$t"; \
      printf '[target.%s]\nlinker = "%s-gcc"\n' "$t" "$p" >> /usr/local/cargo/config.toml; \
      u=$(echo "$t" | tr - _); \
      printf 'CC_%s=%s-gcc\nAR_%s=%s-ar\n' "$u" "$p" "$u" "$p" > /cross-env; \
    else \
      touch /cross-env; \
    fi
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs Rocket.toml ./
COPY types types
COPY engine engine
COPY migrations migrations
COPY src src
COPY static static
COPY locales locales
# Oberfläche aus der Stufe oben; build.rs bettet sie ins Programm ein (Text und WebAssembly
# gzip) – der Server braucht dafür keine Dateien mehr.
COPY --from=ui /out/public ui/dist/public
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,id=nrzdns-target-$TARGETARCH \
    env $(cat /cross-env) cargo build --release --locked --target "$(cat /rust-target)" \
 && cp "target/$(cat /rust-target)/release/nrzdns" /nrzdns \
 && mkdir /data-empty

# ---------------------------------------------------------------- Programm allein
# Für die Release-Anhänge und das Umbrel-Paket: dist/linux_amd64/nrzdns und dist/linux_arm64/nrzdns.
FROM scratch AS binaries
COPY --from=build /nrzdns /nrzdns

# ---------------------------------------------------------------- Laufzeit
# Kein RUN in dieser Stufe: Das Programm bringt seine Wurzelzertifikate (webpki) selbst mit und
# braucht weder ca-certificates noch einen Benutzereintrag – so muss beim arm64-Image nichts
# emuliert werden.
FROM ${DEBIAN} AS runtime
COPY --from=build --chown=1000:1000 /data-empty /data
COPY --from=build /nrzdns /usr/local/bin/nrzdns
COPY Rocket.toml /app/Rocket.toml

WORKDIR /app
# DNS auf Port 53 als Benutzer 1000: Docker erlaubt im Container seit 20.10 alle Ports ohne
# Root (net.ipv4.ip_unprivileged_port_start=0); bei älteren Versionen den sysctl setzen,
# siehe docker-compose.yml.
ENV NRZDNS_CONFIG=/app/Rocket.toml \
    NRZDNS_DATA_DIR=/data \
    NRZDNS_ADDRESS=0.0.0.0 \
    NRZDNS_PORT=8380 \
    NRZDNS_DNS_LISTEN=0.0.0.0:53
USER 1000:1000
VOLUME /data
EXPOSE 8380 53/udp 53/tcp 80
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["nrzdns", "healthcheck"]
STOPSIGNAL SIGTERM
CMD ["nrzdns"]
