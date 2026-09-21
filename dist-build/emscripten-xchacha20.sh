#! /bin/sh
#
# Builds a minimal libsodium distribution containing only
# XChaCha20-Poly1305-IETF (aead) + randombytes + hex/base64 helpers,
# as separate .wasm and .js (ES module) files.
#
# Usage: sh dist-build/emscripten-xchacha20.sh

set -e

cd "$(dirname "$0")/.."

EXPORTED_FUNCTIONS='["_malloc","_free","_crypto_aead_xchacha20poly1305_ietf_abytes","_crypto_aead_xchacha20poly1305_ietf_decrypt","_crypto_aead_xchacha20poly1305_ietf_decrypt_detached","_crypto_aead_xchacha20poly1305_ietf_encrypt","_crypto_aead_xchacha20poly1305_ietf_encrypt_detached","_crypto_aead_xchacha20poly1305_ietf_keybytes","_crypto_aead_xchacha20poly1305_ietf_keygen","_crypto_aead_xchacha20poly1305_ietf_messagebytes_max","_crypto_aead_xchacha20poly1305_ietf_npubbytes","_crypto_aead_xchacha20poly1305_ietf_nsecbytes","_randombytes","_randombytes_buf","_randombytes_buf_deterministic","_randombytes_close","_randombytes_random","_randombytes_seedbytes","_randombytes_stir","_randombytes_uniform","_sodium_base642bin","_sodium_base64_encoded_len","_sodium_bin2base64","_sodium_bin2hex","_sodium_hex2bin","_sodium_init","_sodium_library_minimal","_sodium_library_version_major","_sodium_library_version_minor","_sodium_version_string"]'
EXPORTED_RUNTIME_METHODS='["UTF8ToString","stringToUTF8","lengthBytesUTF8","getValue","setValue"]'

PREFIX="$(pwd)/dist-build/libsodium-js-xchacha20"

CFLAGS="-O3"
LDFLAGS="-s ALLOW_MEMORY_GROWTH=1 -s ASSERTIONS=0 -s DISABLE_EXCEPTION_CATCHING=1 -s EVAL_CTORS=1 -s INITIAL_MEMORY=4MB -s ENVIRONMENT=web,node -s MODULARIZE=1 -s EXPORT_ES6=1"
JS_EXPORTS_FLAGS="-s EXPORTED_FUNCTIONS=${EXPORTED_FUNCTIONS} -s EXPORTED_RUNTIME_METHODS=${EXPORTED_RUNTIME_METHODS}"

rm -rf "$PREFIX"
mkdir -p "$PREFIX"

echo "Building a XChaCha20-Poly1305-only distribution in [$PREFIX]"

if [ ! -f configure ]; then
  echo "Generating configure script..."
  autoreconf -fiv >/dev/null || ./autogen.sh -s
fi

emconfigure ./configure --enable-minimal --disable-shared --prefix="$PREFIX" \
  --without-pthreads --disable-ssp --disable-asm --disable-pie &&
  emmake make clean
[ $? = 0 ] || exit 1

emmake make -j4 install || exit 1

emcc "$CFLAGS" $LDFLAGS $JS_EXPORTS_FLAGS \
  "$PREFIX/lib/libsodium.a" -o "$PREFIX/lib/libsodium.js" || exit 1

echo
ls -l "$PREFIX/lib/libsodium.js" "$PREFIX/lib/libsodium.wasm"
