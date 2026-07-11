#!/usr/bin/env bash
#
# ecc-diff-fuzzer/mayhem/build.sh — build catenacyber/elliptic-curve-differential-fuzzer's
# single OSS-Fuzz harness (fuzz_ec) as a sanitized libFuzzer target (+ standalone reproducer).
#
# ── What this fuzzes ───────────────────────────────────────────────────────────────────────────
# This is a DIFFERENTIAL fuzzer. LLVMFuzzerTestOneInput (fuzz_ec.c) parses each input as:
#   [2 bytes TLS curve group id][big integer / scalar bytes][1 flag byte][compressed point bytes]
# then either multiplies a (decompressed) point by a scalar, or adds two points, on the selected
# elliptic curve — feeding the SAME operation to every linked crypto backend and cross-checking
# that all backends return the identical resulting point (length + bytes). A mismatch (or an
# unexpected error) is the bug oracle: the harness abort()s, which the fuzzer catches as a crash.
#
# ── Tractable backend subset ───────────────────────────────────────────────────────────────────
# The upstream OSS-Fuzz build links ELEVEN backends (mbedtls, libecc, openssl, nettle, gcrypt,
# cryptopp, botan/botanblind, golang, node/elliptic JS, rust), almost all of which require building
# heavy upstream libraries from source plus Go/Rust/Node toolchains (see /tmp/oss-fuzz .../build.sh).
# That is intractable to reproduce faithfully in our base image. We build the TRACTABLE SUBSET that
# the base provides via apt:
#   INCLUDED:  openssl (libssl-dev / libcrypto.a)  — MANDATORY: also defines decompressPoint()
#              nettle  (nettle-dev + libgmp-dev)   — second differential arm (libnettle/libhogweed/libgmp)
#   EXCLUDED:  mbedtls, libecc, gcrypt, cryptopp, botan, botanblind, golang, nodejs/elliptic, rust
#              — provided as FUZZEC_ERROR_UNSUPPORTED stubs (mayhem/harnesses/stubs.c) so upstream's
#                fuzz_ec.c stays UNMODIFIED and the differential loop simply skips them per input.
# openssl-vs-nettle is a real 2-way differential oracle (both implement the prime curves
# secp192r1/224r1/256r1/384r1/521r1 that nettle supports).
#
# Build contract from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). The crypto code we actually drive (the harness + module glue) is compiled
# with $SANITIZER_FLAGS; openssl/nettle themselves come from apt static archives.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

BUILD="$SRC/mayhem-build"
rm -rf "$BUILD"; mkdir -p "$BUILD"

# Add SanitizerCoverage instrumentation at COMPILE time when building for libFuzzer.
# $SANITIZER_FLAGS only carries ASan/UBSan — it does NOT inject coverage edges; that
# requires -fsanitize=fuzzer-no-link (compile-time sancov) in addition to the
# -fsanitize=fuzzer link flag in $LIB_FUZZING_ENGINE. Without this every harness
# object has 0 edges and Mayhem reports "0-edge run" for the target.
# Guard: only add it when LIB_FUZZING_ENGINE references 'fuzzer' (i.e. libFuzzer/
# Centipede); AFL++'s LIB_FUZZING_ENGINE is a .a that does not need this flag.
SANCOV_FLAG=
case "$LIB_FUZZING_ENGINE" in
  *fuzzer*) SANCOV_FLAG="-fsanitize=fuzzer-no-link" ;;
esac

# FUZZ_JS_DISABLED keeps fuzz_ec.c from pulling in the JS init header (genjsinit.h); the JS backend
# is stubbed anyway. -w silences upstream's openssl-3.0 deprecation warnings (the API still works).
CFLAGS_COMMON="$SANITIZER_FLAGS ${SANCOV_FLAG} $DEBUG_FLAGS -DFUZZ_JS_DISABLED -w -I$SRC"

# Backend static libraries provided by the base via apt (see mayhem/Dockerfile USER root step).
BACKEND_LIBS="-lcrypto -lhogweed -lnettle -lgmp -lm"

# ── 1) Compile the harness + the INCLUDED backend module glue + the EXCLUDED-backend stubs ───────
OBJS=()
compile() { # <src> <obj>
  $CC $CFLAGS_COMMON -c "$1" -o "$BUILD/$2"
  OBJS+=("$BUILD/$2")
}
compile "$SRC/fuzz_ec.c"          fuzz_ec.o      # the differential harness (unmodified upstream)
compile "$SRC/modules/openssl.c"  openssl.o      # real openssl backend (+ decompressPoint)
compile "$SRC/modules/nettle.c"   nettle.o       # real nettle backend
compile "$SRC/mayhem/harnesses/stubs.c" stubs.o  # UNSUPPORTED stubs for the excluded backends

# ── 2) libFuzzer target -> /mayhem/fuzz_ec ───────────────────────────────────────────────────────
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "${OBJS[@]}" $LIB_FUZZING_ENGINE $BACKEND_LIBS -o /mayhem/fuzz_ec
echo "built libFuzzer target /mayhem/fuzz_ec"

# ── 3) standalone reproducer (no libFuzzer runtime, reads one input file) -> /mayhem/fuzz_ec-standalone ──
# The base ships a generic StandaloneFuzzTargetMain.c (single-file run-once driver). Compile it as an
# object and link the SAME harness objects against it instead of libFuzzer.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "${OBJS[@]}" "$BUILD/standalone_main.o" $BACKEND_LIBS -o /mayhem/fuzz_ec-standalone
echo "built standalone reproducer /mayhem/fuzz_ec-standalone"

# ── 4) fuzz_ec_noblocker variant (OSS-Fuzz parity: link identical objects with different name) ───────
# The noblocker variant is built identically in our tractable subset (JS is already disabled).
# We ship it to maintain full OSS-Fuzz harness parity.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "${OBJS[@]}" $LIB_FUZZING_ENGINE $BACKEND_LIBS -o /mayhem/fuzz_ec_noblocker
echo "built libFuzzer target /mayhem/fuzz_ec_noblocker"

# ── 5) standalone reproducer for noblocker -> /mayhem/fuzz_ec_noblocker-standalone ──
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "${OBJS[@]}" "$BUILD/standalone_main.o" $BACKEND_LIBS -o /mayhem/fuzz_ec_noblocker-standalone
echo "built standalone reproducer /mayhem/fuzz_ec_noblocker-standalone"

echo "build.sh complete:"
ls -la /mayhem/fuzz_ec* 2>&1 || true
