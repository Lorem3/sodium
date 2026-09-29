#! /bin/sh
#
# Native (host) thin static library: only XChaCha20-Poly1305 + deps.
# Verifies that forbidden primitives are not compiled into the archive.
#
# Usage: sh dist-build/build-xchacha20-native.sh

set -e

cd "$(dirname "$0")/.."

SRC="src/libsodium"
PREFIX="$(pwd)/dist-build/libsodium-native-xchacha20"
OBJDIR="$PREFIX/obj"

SOURCES="
${SRC}/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c
${SRC}/crypto_core/hchacha20/core_hchacha20.c
${SRC}/crypto_stream/chacha20/stream_chacha20.c
${SRC}/crypto_stream/chacha20/ref/chacha20_ref.c
${SRC}/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c
${SRC}/crypto_onetimeauth/poly1305/donna/poly1305_donna.c
${SRC}/crypto_verify/sodium/verify.c
${SRC}/randombytes/randombytes.c
${SRC}/randombytes/sysrandom/randombytes_sysrandom.c
${SRC}/sodium/core.c
${SRC}/sodium/runtime.c
${SRC}/sodium/utils.c
${SRC}/sodium/version.c
dist-build/xchacha20-unused-stubs.c
"

rm -rf "$PREFIX"
mkdir -p "$OBJDIR" "$PREFIX/lib"

if [ ! -f Makefile ]; then
  if [ ! -f configure ]; then
    autoreconf -fiv >/dev/null || ./autogen.sh -s
  fi
  ./configure --enable-minimal --disable-shared --disable-asm --prefix="$PREFIX" >/dev/null
fi

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
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2}"

OBJS=""
for src in $SOURCES; do
  base=$(basename "$src" .c)
  obj="$OBJDIR/${base}.o"
  # shellcheck disable=SC2086
  $CC $CFLAGS @"$OBJDIR/defs.rsp" $CPPFLAGS -c "$src" -o "$obj"
  OBJS="$OBJS $obj"
done

# shellcheck disable=SC2086
ar rcs "$PREFIX/lib/libsodium-xchacha20.a" $OBJS

echo "Thin archive: $PREFIX/lib/libsodium-xchacha20.a"
ls -l "$PREFIX/lib/libsodium-xchacha20.a"
if [ -f src/libsodium/.libs/libsodium.a ]; then
  echo "Full minimal archive for comparison:"
  ls -l src/libsodium/.libs/libsodium.a
fi

if nm "$PREFIX/lib/libsodium-xchacha20.a" | grep -E ' T _?crypto_(aead_aegis|pwhash_argon|sign_ed25519|secretstream|box_curve|aead_chacha20poly1305_)' >/dev/null; then
  echo "ERROR: forbidden crypto symbols present" >&2
  nm "$PREFIX/lib/libsodium-xchacha20.a" | grep -E ' T _?crypto_(aead_aegis|pwhash_argon|sign_ed25519|secretstream|box_curve|aead_chacha20poly1305_)' >&2 || true
  exit 1
fi

if ! nm "$PREFIX/lib/libsodium-xchacha20.a" | grep -E 'crypto_aead_xchacha20poly1305_ietf_encrypt_init' >/dev/null; then
  echo "ERROR: missing streaming encrypt_init" >&2
  exit 1
fi

echo "OK: thin native archive contains XChaCha20-Poly1305 only (no argon2/secretstream/ed25519/...)."
