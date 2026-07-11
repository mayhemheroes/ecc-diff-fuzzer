// mayhem/harnesses/stubs.c
//
// ecc-diff-fuzzer is a DIFFERENTIAL fuzzer: upstream's fuzz_ec.c iterates a fixed
// modules[] table (NBMODULES = 11) and cross-checks every backend's EC result against
// the others. The full OSS-Fuzz build links ELEVEN crypto backends (mbedtls, libecc,
// openssl, nettle, gcrypt, cryptopp, botan + botanblind, golang, node/elliptic JS, rust),
// most of which require building heavy upstream libraries from source plus Go/Rust/Node
// toolchains — intractable to reproduce faithfully in our base image.
//
// Our TRACTABLE SUBSET links the two backends available as apt packages in the base:
//   - openssl  (libssl-dev / libcrypto.a)  — MANDATORY: also defines decompressPoint()
//   - nettle   (nettle-dev + libgmp-dev)   — the second oracle arm
// That is a genuine 2-way differential oracle (openssl vs nettle agreement at runtime).
//
// To keep upstream's fuzz_ec.c BYTE-FOR-BYTE UNMODIFIED (so the additive layer stays a
// clean, additive integration and future syncs rebase cleanly), this file provides the
// symbols fuzz_ec.c references for the EXCLUDED backends. Each stub reports
// FUZZEC_ERROR_UNSUPPORTED, so the differential loop simply skips that module for every
// input — exactly as if the curve were unsupported by that backend. The init() stubs
// succeed so initialization does not bail out.
//
// NOTE: openssl and nettle are NOT stubbed here — their real implementations come from
// modules/openssl.c and modules/nettle.c, which build.sh compiles and links.

#include "../../fuzz_ec.h"

#define ECC_DIFF_STUB_PROCESS(fn) \
    void fn(fuzzec_input_t *input, fuzzec_output_t *output) { \
        (void)input; \
        output->errorCode = FUZZEC_ERROR_UNSUPPORTED; \
    }

// mbedtls
ECC_DIFF_STUB_PROCESS(fuzzec_mbedtls_process)
ECC_DIFF_STUB_PROCESS(fuzzec_mbedtls_add)
// libecc
ECC_DIFF_STUB_PROCESS(fuzzec_libecc_process)
ECC_DIFF_STUB_PROCESS(fuzzec_libecc_add)
// gcrypt
ECC_DIFF_STUB_PROCESS(fuzzec_gcrypt_process)
ECC_DIFF_STUB_PROCESS(fuzzec_gcrypt_add)
// cryptopp
ECC_DIFF_STUB_PROCESS(fuzzec_cryptopp_process)
ECC_DIFF_STUB_PROCESS(fuzzec_cryptopp_add)
// botan (+ blinded variant)
ECC_DIFF_STUB_PROCESS(fuzzec_botan_process)
ECC_DIFF_STUB_PROCESS(fuzzec_botan_add)
ECC_DIFF_STUB_PROCESS(fuzzec_botanblind_process)
// golang
ECC_DIFF_STUB_PROCESS(fuzzec_golang_process)
ECC_DIFF_STUB_PROCESS(fuzzec_golang_add)
// node/elliptic JS
ECC_DIFF_STUB_PROCESS(fuzzec_js_process)
ECC_DIFF_STUB_PROCESS(fuzzec_js_add)
// rust
ECC_DIFF_STUB_PROCESS(fuzzec_rust_process)

// init() stubs for the excluded backends that declare one (must succeed → return 0).
int fuzzec_gcrypt_init(void) { return 0; }
int fuzzec_js_init(void) { return 0; }
