#!/usr/bin/env bash
# Pin both the release and artifact bytes used by scan integration tests.
set -euo pipefail
version=v1.22.0
case "$RUNNER_OS" in
  Linux)
    asset="yara-x-${version}-x86_64-unknown-linux-gnu.tar.gz"
    checksum=7f470770b2c1a0d97f02298fc194978d999074d147d003d33dd62775761439db
    binary=yr
    ;;
  Windows)
    asset="yara-x-${version}-x86_64-pc-windows-msvc.zip"
    checksum=eac36a58699b94d3732a7fe1d8453fe89e0077bb18ac2c99b4c2ee102a431f2e
    binary=yr.exe
    ;;
  *) printf 'Unsupported CI runner: %s\n' "$RUNNER_OS" >&2; exit 1 ;;
esac
temp="$(mktemp -d)"
trap 'rm -rf -- "$temp"' EXIT
curl --fail --location --retry 3 "https://github.com/VirusTotal/yara-x/releases/download/${version}/${asset}" -o "$temp/$asset"
printf '%s  %s\n' "$checksum" "$temp/$asset" | sha256sum --check --strict
mkdir -p bin
if [ "$RUNNER_OS" = Windows ]; then
  unzip -q "$temp/$asset" -d "$temp/extract"
else
  mkdir "$temp/extract"
  tar -xzf "$temp/$asset" -C "$temp/extract"
fi
cp "$temp/extract/$binary" "bin/$binary"
if [ "$RUNNER_OS" = Windows ]; then
  cygpath -w "$(pwd)/bin" >> "$GITHUB_PATH"
else
  chmod +x "bin/$binary"
  printf '%s/bin\n' "$PWD" >> "$GITHUB_PATH"
fi
"./bin/$binary" --version
