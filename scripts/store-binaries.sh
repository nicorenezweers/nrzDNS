#!/bin/sh
# Programm für linux/amd64 und linux/arm64 bauen und gzip-komprimiert für die Umbrel-App ablegen:
#   scripts/store-binaries.sh ../nrzStore/nrz-dns/hooks/app-files/nrzdns
# Ergebnis: <ordner>/nrzdns-amd64.gz und <ordner>/nrzdns-arm64.gz. hooks/pre-start der App entpackt
# die passende Datei nach ${APP_DATA_DIR}/app/nrzdns; die Oberfläche steckt schon im Programm.
# Braucht nur Docker mit buildx (Rust wird im Dockerfile quer-kompiliert, nichts wird emuliert).
# Jede Architektur wird einzeln gebaut – das klappt auch mit dem einfachen docker-Builder, der
# keine Multi-Plattform-Builds kann.
set -eu

if [ $# -ne 1 ]; then
  echo "Aufruf: $0 <zielordner>" >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$1"
dest="$(cd "$1" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for arch in amd64 arm64; do
  docker buildx build --platform "linux/$arch" --target binaries \
    --output "type=local,dest=$tmp/$arch" "$root"
  bin="$tmp/$arch/nrzdns"
  if [ ! -s "$bin" ]; then
    echo "Programm fehlt: $bin" >&2
    exit 1
  fi
  # ELF-Kopf prüfen (e_machine: 62 = x86-64, 183 = AArch64) – ein Programm für die falsche
  # Architektur startet auf dem Gerät nicht.
  machine="$(od -An -tu1 -j18 -N1 "$bin" | tr -d ' ')"
  case "$arch:$machine" in
    amd64:62 | arm64:183) ;;
    *) echo "$bin ist nicht für $arch gebaut (e_machine $machine)" >&2; exit 1 ;;
  esac
  gzip -9 -n -c "$bin" > "$dest/nrzdns-$arch.gz.new"
  mv -f "$dest/nrzdns-$arch.gz.new" "$dest/nrzdns-$arch.gz"
done

ls -l "$dest"/nrzdns-*.gz
