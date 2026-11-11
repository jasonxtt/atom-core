#!/usr/bin/env bash
# Builds the atomdns program (the pure Rust host). It embeds no WebUI: the WebUI is the separate
# package `npm run build` / `npm run build:package` in webui (installed as <config root>/ui/main/).
# Cross builds: CARGO_BUILD_TARGET=<triple> (and CARGO_SUBCOMMAND=zigbuild for the musl and ARM glibc targets, see
# build-rust-release.sh); the finished program must be runnable here (natively or through qemu-user).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
VERSION="${BUILD_VERSION:-$(git describe --tags --match 'v*' --always --dirty 2>/dev/null || echo dev)}"
export ATOMDNS_BUILD_VERSION="${VERSION}"
OUTPUT="$(node -e 'console.log(require("node:path").resolve(process.argv[1]))' "${OUTPUT:-release/atomdns-native}")"
MANIFEST="${OUTPUT}.manifest.json"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT_DIR}/rust/target}"
mkdir -p "$(dirname "${OUTPUT}")"
node scripts/native-build-manifest.mjs prepare "${MANIFEST}"
SOURCE_DIGEST="$(node -e 'console.log(JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8")).source_manifest_sha256)' "${MANIFEST}")"
# A source-keyed directory prevents older restored mtimes from reusing a stale executable.
NATIVE_TARGET_DIR="${CARGO_TARGET_DIR}/native-${SOURCE_DIGEST}"
# cargo itself rejects <triple>.<glibc version> in CARGO_BUILD_TARGET; cargo-zigbuild only understands it as --target.
TARGET_ARGS=()
case "${CARGO_BUILD_TARGET:-}" in
  *-gnu*.[0-9]*.[0-9]*) TARGET_ARGS=(--target "${CARGO_BUILD_TARGET}"); ZIG_TARGET="${CARGO_BUILD_TARGET}"; unset CARGO_BUILD_TARGET ;;
esac
cargo "${CARGO_SUBCOMMAND:-build}" ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"} --locked --manifest-path rust/Cargo.toml -p atomdns-native-host --release --target-dir "${NATIVE_TARGET_DIR}"
# cargo-zigbuild accepts <triple>.<glibc version> (e.g. aarch64-unknown-linux-gnu.2.35); cargo's own directory has only the triple.
TARGET_DIR_NAME="${ZIG_TARGET:-${CARGO_BUILD_TARGET:-}}"
case "${TARGET_DIR_NAME}" in *-gnu*.[0-9]*.[0-9]*) TARGET_DIR_NAME="${TARGET_DIR_NAME%.*.*}" ;; esac
ARTIFACT="${NATIVE_TARGET_DIR}/${TARGET_DIR_NAME:+${TARGET_DIR_NAME}/}release/atomdns"
if [[ "${ARTIFACT}" != "${OUTPUT}" ]]; then cp "${ARTIFACT}" "${OUTPUT}"; fi
node scripts/native-build-manifest.mjs finish "${MANIFEST}" "${OUTPUT}"
echo "built ${OUTPUT} (version=${VERSION}; manifest=${MANIFEST})"
