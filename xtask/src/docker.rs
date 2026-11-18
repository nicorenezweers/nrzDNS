//! Docker: das Dockerfile (als Rust-Konstante, die Tailwind-Eingabe der Oberfläche steckt als
//! Heredoc darin) und die Builds damit. `docker buildx build --file -` liest es von der
//! Standardeingabe; wer eine Datei braucht (CI, `docker build .`, `docker compose build`),
//! schreibt sie mit `cargo xtask dockerfile > Dockerfile`.

use crate::{root, tailwind, Result};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Platzhalter in [`TEMPLATE`] für die Tailwind-Eingabe.
const TAILWIND: &str = "@@TAILWIND_CSS@@\n";
/// Ende des Heredocs mit der Tailwind-Eingabe (in Anführungszeichen: ohne Variablenersetzung).
const HEREDOC_END: &str = "NRZ_TAILWIND_CSS";

/// Das Dockerfile, wie `docker build` es bekommt.
pub fn dockerfile() -> String {
    let heredoc = format!(
        "COPY <<\"{HEREDOC_END}\" ui/tailwind.css\n{}{HEREDOC_END}\n",
        tailwind::INPUT
    );
    TEMPLATE.replacen(TAILWIND, &heredoc, 1)
}

/// `docker buildx build` mit diesem Dockerfile; die Optionen gehen unverändert an Docker, der
/// Kontext ist immer der Hauptordner.
pub fn build(args: &[String]) -> Result {
    buildx(args.iter().map(String::as_str))
}

fn buildx<'a>(args: impl IntoIterator<Item = &'a str>) -> Result {
    let mut child = Command::new("docker")
        .args(["buildx", "build", "--file", "-"])
        .args(args)
        .arg(root())
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("docker lässt sich nicht starten: {e}"))?;
    // Nach dem Schreiben schliessen, damit Docker das Ende des Dockerfiles sieht.
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(dockerfile().as_bytes())?;
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("docker buildx build ist fehlgeschlagen ({status})").into())
    }
}

/// Programm für linux/amd64 und linux/arm64 bauen und gzip-komprimiert für die Umbrel-App
/// ablegen: `<ordner>/nrzdns-amd64.gz` und `<ordner>/nrzdns-arm64.gz`. `hooks/pre-start` der App
/// entpackt die passende Datei nach `${APP_DATA_DIR}/app/nrzdns`; die Oberfläche steckt schon im
/// Programm. Braucht nur Docker mit buildx (Rust wird im Dockerfile quer-kompiliert, nichts wird
/// emuliert). Jede Architektur wird einzeln gebaut – das klappt auch mit dem einfachen
/// docker-Builder, der keine Multi-Plattform-Builds kann.
pub fn store_binaries(dest: &Path) -> Result {
    fs::create_dir_all(dest)?;
    let tmp = TempDir::new()?;
    // e_machine im ELF-Kopf: 62 = x86-64, 183 = AArch64
    for (arch, machine) in [("amd64", 62), ("arm64", 183)] {
        let out = tmp.0.join(arch);
        buildx([
            "--platform",
            &format!("linux/{arch}"),
            "--target",
            "binaries",
            "--output",
            &format!("type=local,dest={}", out.display()),
        ])?;
        let bin = out.join("nrzdns");
        check_elf(&bin, machine).map_err(|e| format!("{}: {e}", bin.display()))?;

        let target = dest.join(format!("nrzdns-{arch}.gz"));
        let partial = dest.join(format!("nrzdns-{arch}.gz.new"));
        let mut gz =
            flate2::write::GzEncoder::new(File::create(&partial)?, flate2::Compression::best());
        io::copy(&mut File::open(&bin)?, &mut gz)?;
        gz.finish()?.sync_all()?;
        fs::rename(&partial, &target)?;
        println!(
            "{} ({:.1} MiB)",
            target.display(),
            fs::metadata(&target)?.len() as f64 / (1024.0 * 1024.0)
        );
    }
    Ok(())
}

/// Ein Programm für die falsche Architektur startet auf dem Gerät nicht – vorher prüfen.
fn check_elf(bin: &Path, machine: u16) -> Result {
    let mut head = [0u8; 20];
    File::open(bin)
        .and_then(|mut f| f.read_exact(&mut head))
        .map_err(|e| format!("Programm fehlt oder ist leer ({e})"))?;
    if &head[..4] != b"\x7fELF" {
        return Err("kein ELF-Programm".into());
    }
    let found = u16::from_le_bytes([head[18], head[19]]);
    if found != machine {
        return Err(format!("für die falsche Architektur gebaut (e_machine {found})").into());
    }
    Ok(())
}

/// Temporärer Ordner, der am Ende wieder verschwindet.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            std::env::temp_dir().join(format!("nrzdns-binaries-{}-{stamp}", std::process::id()));
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Dockerfile; [`TAILWIND`] wird durch die Tailwind-Eingabe ersetzt.
const TEMPLATE: &str = r#"# syntax=docker/dockerfile:1.10
# nrzNetwork – Multi-Stage-Build für amd64 und arm64: Oberfläche (Dioxus/WebAssembly), DNS-Engine
# und Server (Rust) in einer Datei. Erzeugt von `cargo xtask dockerfile` (xtask/src/docker.rs);
# der Build selbst braucht nur Docker – Rust läuft ausschliesslich in den Build-Stufen.
#   cargo xtask docker -t nrzdns
#   docker run -p 53:53/udp -p 53:53/tcp -p 8380:8380 -p 80:80 -v nrzdns-data:/data nrzdns
# Beide Architekturen (Rust wird quer-kompiliert, nicht emuliert):
#   cargo xtask docker --platform linux/amd64,linux/arm64 -t <registry>/nrz-dns:<version> --push
# Nur das Programm für beide Architekturen (landet in dist/linux_<arch>/nrzdns):
#   cargo xtask docker --platform linux/amd64,linux/arm64 --target binaries --output type=local,dest=dist
# Fürs Umbrel-Paket (gzip, nrzdns-amd64.gz / nrzdns-arm64.gz): cargo xtask store-binaries <ordner>

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
# Tailwind-Eingabe aus ui/tailwind.rs; dx findet ui/tailwind.css und übersetzt sie vor dem Build.
@@TAILWIND_CSS@@
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
# Mitglied des Workspace: wird hier nicht übersetzt, Cargo braucht aber sein Manifest.
COPY xtask xtask
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
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dockerfile_carries_the_tailwind_input() {
        let file = dockerfile();
        assert!(file.starts_with("# syntax=docker/dockerfile:"));
        assert!(!file.contains(TAILWIND.trim_end()));
        let start = format!("COPY <<\"{HEREDOC_END}\" ui/tailwind.css\n");
        let body = file.split_once(&start).expect("Heredoc fehlt").1;
        let end = format!("\n{HEREDOC_END}\n");
        let css = &body[..body.find(&end).expect("Heredoc-Ende fehlt") + 1];
        assert_eq!(css, tailwind::INPUT);
    }

    #[test]
    fn tailwind_input_fits_into_the_heredoc() {
        assert!(tailwind::INPUT.ends_with('\n'));
        assert!(!tailwind::INPUT.lines().any(|l| l == HEREDOC_END));
    }
}
