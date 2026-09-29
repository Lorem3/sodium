#! /bin/sh
#
# Builds a true XChaCha20-Poly1305-only wasm/js distribution:
# only the AEAD (+ streaming) and its hard dependencies are compiled.
# ChaCha20-Poly1305 (non-x), secretstream, argon2, box, sign, etc. are
# not compiled into the binary.
#
# Usage: sh dist-build/emscripten-xchacha20.sh

set -e

cd "$(dirname "$0")/.."

SRC="src/libsodium"
PREFIX="$(pwd)/dist-build/libsodium-js-xchacha20"
OBJDIR="$PREFIX/obj"

EXPORTED_FUNCTIONS='["_malloc","_free","_crypto_aead_xchacha20poly1305_ietf_abytes","_crypto_aead_xchacha20poly1305_ietf_decrypt","_crypto_aead_xchacha20poly1305_ietf_decrypt_detached","_crypto_aead_xchacha20poly1305_ietf_decrypt_final","_crypto_aead_xchacha20poly1305_ietf_decrypt_init","_crypto_aead_xchacha20poly1305_ietf_decrypt_update","_crypto_aead_xchacha20poly1305_ietf_encrypt","_crypto_aead_xchacha20poly1305_ietf_encrypt_detached","_crypto_aead_xchacha20poly1305_ietf_encrypt_final","_crypto_aead_xchacha20poly1305_ietf_encrypt_init","_crypto_aead_xchacha20poly1305_ietf_encrypt_update","_crypto_aead_xchacha20poly1305_ietf_keybytes","_crypto_aead_xchacha20poly1305_ietf_keygen","_crypto_aead_xchacha20poly1305_ietf_messagebytes_max","_crypto_aead_xchacha20poly1305_ietf_npubbytes","_crypto_aead_xchacha20poly1305_ietf_nsecbytes","_crypto_aead_xchacha20poly1305_ietf_statebytes","_randombytes_buf","_sodium_init","_sodium_library_minimal","_sodium_library_version_major","_sodium_library_version_minor","_sodium_version_string"]'
EXPORTED_RUNTIME_METHODS='["UTF8ToString","getValue","setValue","HEAPU8"]'

CFLAGS="-O3"
LDFLAGS="-s ALLOW_MEMORY_GROWTH=1 -s ASSERTIONS=0 -s DISABLE_EXCEPTION_CATCHING=1 -s EVAL_CTORS=1 -s INITIAL_MEMORY=4MB -s ENVIRONMENT=web,node -s MODULARIZE=1 -s EXPORT_ES6=1"
JS_EXPORTS_FLAGS="-s EXPORTED_FUNCTIONS=${EXPORTED_FUNCTIONS} -s EXPORTED_RUNTIME_METHODS=${EXPORTED_RUNTIME_METHODS}"

SOURCES="
${SRC}/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c
${SRC}/crypto_core/hchacha20/core_hchacha20.c
${SRC}/crypto_stream/chacha20/stream_chacha20.c
${SRC}/crypto_stream/chacha20/ref/chacha20_ref.c
${SRC}/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
${SRC}/crypto_onetimeauth/poly1305/donna/poly1305_donna.c
${SRC}/crypto_verify/sodium/verify.c
${SRC}/randombytes/randombytes.c
${SRC}/sodium/core.c
${SRC}/sodium/runtime.c
${SRC}/sodium/utils.c
${SRC}/sodium/version.c
dist-build/xchacha20-unused-stubs.c
"

rm -rf "$PREFIX"
mkdir -p "$PREFIX/lib" "$OBJDIR"

echo "Building an XChaCha20-Poly1305-only distribution in [$PREFIX]"

if [ ! -f configure ]; then
  echo "Generating configure script..."
  autoreconf -fiv >/dev/null || ./autogen.sh -s
fi

# Produce config / version headers and compiler DEFS (no full library build).
emconfigure ./configure --enable-minimal --disable-shared --prefix="$PREFIX" \
  --without-pthreads --disable-ssp --disable-asm --disable-pie \
  >/dev/null
[ $? = 0 ] || exit 1

# Expand autoconf DEFS into a compiler response file (handles make \-escapes).
python3 - "$OBJDIR/defs.rsp" <<'PY'
import pathlib, re, shlex, sys
out = pathlib.Path(sys.argv[1])
text = pathlib.Path("Makefile").read_text()
m = re.search(r"^DEFS = (.*)$", text, re.M)
if not m:
    raise SystemExit("DEFS not found in Makefile")
raw = m.group(1).replace("\\ ", " ").replace('\\"', '"')
flags = shlex.split(raw)
# Drop package metadata; values with spaces break clang @file tokenization.
flags = [f for f in flags if not f.startswith(("-DPACKAGE", "-DVERSION="))]
out.write_text("\n".join(flags) + "\n")
PY
CPPFLAGS="-I. -I${SRC}/include -I${SRC}/include/sodium -DDEV_MODE=1"

echo "Compiling only XChaCha20-Poly1305 sources..."
OBJS=""
for src in $SOURCES; do
  base=$(basename "$src" .c)
  obj="$OBJDIR/${base}.o"
  # shellcheck disable=SC2086
  emcc $CFLAGS @"$OBJDIR/defs.rsp" $CPPFLAGS -c "$src" -o "$obj"
  OBJS="$OBJS $obj"
done

# shellcheck disable=SC2086
emcc $CFLAGS $LDFLAGS $JS_EXPORTS_FLAGS $OBJS -o "$PREFIX/lib/libsodium.js"

echo
ls -l "$PREFIX/lib/libsodium.js" "$PREFIX/lib/libsodium.wasm"

# Sanity: forbidden symbols must not appear in the wasm.
if command -v llvm-nm >/dev/null 2>&1 || command -v nm >/dev/null 2>&1; then
  NM=nm
  command -v llvm-nm >/dev/null 2>&1 && NM=llvm-nm
  if $NM "$PREFIX/lib/libsodium.wasm" 2>/dev/null | grep -E 'argon2|ed25519|secretstream|aegis|blake2b|scrypt|curve25519' >/dev/null; then
    echo "ERROR: trimmed wasm still contains forbidden symbols" >&2
    $NM "$PREFIX/lib/libsodium.wasm" 2>/dev/null | grep -E 'argon2|ed25519|secretstream|aegis|blake2b|scrypt|curve25519' >&2 || true
    exit 1
  fi
  echo "Symbol check passed (no argon2/ed25519/secretstream/aegis/...)."
fi
