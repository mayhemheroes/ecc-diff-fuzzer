# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile (SMALL form) — builds ON TOP of the org C/C++ base image
# (ghcr.io/mayhemheroes/base). The base provides debian + clang/llvm + libFuzzer/afl++ +
# the identities + the build-contract ENV; this only adds the per-commit ecc-diff-fuzzer build.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) \
#       [--build-arg SOURCE_DATE_EPOCH=$(date +%s)] \
#       -t ecc-diff-fuzzer-commit:test .

FROM ghcr.io/mayhemheroes/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); never bake it as ENV — an empty value
# breaks clang. build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: the base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# Declare it WITHOUT a default so an unset arg lets the base ENV flow through; --build-arg overrides.
ARG SANITIZER_FLAGS
ARG MAYHEM_JOBS=

# The TRACTABLE differential subset links two crypto backends available as apt packages:
#   openssl: the base already ships libssl-dev (libcrypto.a).
#   nettle : nettle-dev + libgmp-dev (libnettle.a / libhogweed.a / libgmp.a) — install as root.
USER root
RUN apt-get update \
 && apt-get install -yq --no-install-recommends nettle-dev libgmp-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*
USER mayhem

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history)
# is copied to /mayhem as `mayhem`; build.sh builds in place.
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# No mayhem/test.sh: this is a differential fuzzer whose oracle (cross-backend agreement) is a
# RUNTIME property exercised by fuzzing — there is no standalone known-answer suite to run at
# build time. See the note in mayhem/build.sh and the integration report.

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
