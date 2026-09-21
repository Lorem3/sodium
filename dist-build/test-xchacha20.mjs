// Test for the XChaCha20-Poly1305-only libsodium wasm build.
// Usage: node dist-build/test-xchacha20.mjs

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const libDir = join(here, 'libsodium-js-xchacha20', 'lib');

// The emscripten ES6 output is named .js; make sure Node loads it as ESM.
mkdirSync(libDir, { recursive: true });
writeFileSync(join(libDir, 'package.json'), '{"type":"module"}');

const { default: sodiumFactory } = await import(
  pathToFileURL(join(libDir, 'libsodium.js')).href
);

let failed = 0;
function assert(cond, msg) {
  if (!cond) {
    console.error('FAIL:', msg);
    failed++;
  }
}

const sodium = await sodiumFactory();
assert(sodium._sodium_init() === 0, 'sodium_init');

assert(sodium._sodium_library_version_major() === 11, 'library_version_major');
assert(sodium._sodium_library_version_minor() === 0, 'library_version_minor');

const keybytes = sodium._crypto_aead_xchacha20poly1305_ietf_keybytes();
const nsecbytes = sodium._crypto_aead_xchacha20poly1305_ietf_nsecbytes();
const npubbytes = sodium._crypto_aead_xchacha20poly1305_ietf_npubbytes();
const abytes = sodium._crypto_aead_xchacha20poly1305_ietf_abytes();
const maxbytes = sodium._crypto_aead_xchacha20poly1305_ietf_messagebytes_max();

assert(keybytes === 32, 'keybytes === 32');
assert(nsecbytes === 0, 'nsecbytes === 0');
assert(npubbytes === 24, 'npubbytes === 24');
assert(abytes === 16, 'abytes === 16');
const sizemax = 4294967295;
const expectedMax = sizemax - abytes; // SIZE_MAX - 16
assert(
  maxbytes === expectedMax || maxbytes === expectedMax - 2 ** 32,
  'messagebytes_max === SIZE_MAX - abytes'
);

const keyPtr = sodium._malloc(keybytes);
const npubPtr = sodium._malloc(npubbytes);
sodium._crypto_aead_xchacha20poly1305_ietf_keygen(keyPtr);
sodium._randombytes_buf(npubPtr, npubbytes);

const msg = 'hello, world! 你好,世界 — xchacha20poly1305 roundtrip';
const msgBytes = new TextEncoder().encode(msg);
const msgPtr = sodium._malloc(msgBytes.length);
sodium.HEAPU8.set(msgBytes, msgPtr);

const clenPtr = sodium._malloc(8);
const ctPtr = sodium._malloc(msgBytes.length + abytes);

let rc = sodium._crypto_aead_xchacha20poly1305_ietf_encrypt(
  ctPtr, clenPtr, msgPtr, BigInt(msgBytes.length), 0, 0n, 0, npubPtr, keyPtr
);
assert(rc === 0, 'encrypt rc === 0');
const clen = Number(sodium.getValue(clenPtr, 'i64'));
assert(clen === msgBytes.length + abytes, 'clen === mlen + abytes');

const decPtr = sodium._malloc(clen);
const dlenPtr = sodium._malloc(8);
rc = sodium._crypto_aead_xchacha20poly1305_ietf_decrypt(
  decPtr, dlenPtr, 0, ctPtr, BigInt(clen), 0, 0n, npubPtr, keyPtr
);
assert(rc === 0, 'decrypt rc === 0');
const dlen = Number(sodium.getValue(dlenPtr, 'i64'));
assert(dlen === msgBytes.length, 'dlen === mlen');
const decrypted = new TextDecoder().decode(sodium.HEAPU8.subarray(decPtr, decPtr + dlen));
assert(decrypted === msg, 'roundtrip text matches');

sodium.HEAPU8[ctPtr] ^= 1;
rc = sodium._crypto_aead_xchacha20poly1305_ietf_decrypt(
  decPtr, dlenPtr, 0, ctPtr, BigInt(clen), 0, 0n, npubPtr, keyPtr
);
assert(rc === -1, 'tampered ciphertext rejected');
sodium.HEAPU8[ctPtr] ^= 1;

const badKeyPtr = sodium._malloc(keybytes);
sodium._crypto_aead_xchacha20poly1305_ietf_keygen(badKeyPtr);
rc = sodium._crypto_aead_xchacha20poly1305_ietf_decrypt(
  decPtr, dlenPtr, 0, ctPtr, BigInt(clen), 0, 0n, npubPtr, badKeyPtr
);
assert(rc === -1, 'wrong key rejected');

const macPtr = sodium._malloc(abytes);
const mdlenPtr = sodium._malloc(8);
rc = sodium._crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
  ctPtr, macPtr, mdlenPtr, msgPtr, BigInt(msgBytes.length), 0, 0n, 0, npubPtr, keyPtr
);
assert(rc === 0, 'encrypt_detached rc === 0');
const mlen2 = Number(sodium.getValue(mdlenPtr, 'i64'));
assert(mlen2 === abytes, 'detached: maclenp === abytes');
rc = sodium._crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
  decPtr, 0, ctPtr, BigInt(msgBytes.length), macPtr, 0, 0n, npubPtr, keyPtr
);
assert(rc === 0, 'decrypt_detached rc === 0');
const detachedText = new TextDecoder().decode(
  sodium.HEAPU8.subarray(decPtr, decPtr + msgBytes.length)
);
assert(detachedText === msg, 'detached roundtrip matches');

// --- streaming (secretstream_xchacha20poly1305) ---
const ssKeybytes = sodium._crypto_secretstream_xchacha20poly1305_keybytes();
const ssHeaderbytes = sodium._crypto_secretstream_xchacha20poly1305_headerbytes();
const ssAbytes = sodium._crypto_secretstream_xchacha20poly1305_abytes();
const ssStatebytes = sodium._crypto_secretstream_xchacha20poly1305_statebytes();
assert(ssKeybytes === 32, 'secretstream keybytes === 32');
assert(ssHeaderbytes === 24, 'secretstream headerbytes === 24');
assert(ssAbytes === 17, 'secretstream abytes === 17');

const TAG_MESSAGE = sodium._crypto_secretstream_xchacha20poly1305_tag_message();
const TAG_FINAL = sodium._crypto_secretstream_xchacha20poly1305_tag_final();

const ssKeyPtr = sodium._malloc(ssKeybytes);
sodium._crypto_secretstream_xchacha20poly1305_keygen(ssKeyPtr);
const ssHeaderPtr = sodium._malloc(ssHeaderbytes);
const statePush = sodium._malloc(ssStatebytes);
assert(sodium._crypto_secretstream_xchacha20poly1305_init_push(statePush, ssHeaderPtr, ssKeyPtr) === 0, 'init_push');

const pushChunk = (chunk, tag) => {
  const bytes = new TextEncoder().encode(chunk);
  const mPtr = sodium._malloc(bytes.length);
  sodium.HEAPU8.set(bytes, mPtr);
  const cPtr = sodium._malloc(bytes.length + ssAbytes);
  const cLenPtr = sodium._malloc(8);
  const rc = sodium._crypto_secretstream_xchacha20poly1305_push(
    statePush, cPtr, cLenPtr, mPtr, BigInt(bytes.length), 0, 0n, tag
  );
  const clen = Number(sodium.getValue(cLenPtr, 'i64'));
  if (rc !== 0 || clen !== bytes.length + ssAbytes) return null;
  return { cPtr, clen, size: bytes.length };
};

const pullChunk = (state, cPtr, clen, size) => {
  const mPtr = sodium._malloc(size);
  const tagPtr = sodium._malloc(1);
  const rc = sodium._crypto_secretstream_xchacha20poly1305_pull(
    state, mPtr, sodium._malloc(8), tagPtr, cPtr, BigInt(clen), 0, 0n
  );
  if (rc !== 0) return null;
  return {
    text: new TextDecoder().decode(sodium.HEAPU8.subarray(mPtr, mPtr + size)),
    tag: sodium.HEAPU8[tagPtr],
  };
};

const chunks = ['first chunk 你好', 'second chunk', 'final chunk'];
const pushed = [
  pushChunk(chunks[0], TAG_MESSAGE),
  pushChunk(chunks[1], TAG_MESSAGE),
  pushChunk(chunks[2], TAG_FINAL),
];
assert(pushed.every(Boolean), 'push all chunks');

const statePull = sodium._malloc(ssStatebytes);
assert(sodium._crypto_secretstream_xchacha20poly1305_init_pull(statePull, ssHeaderPtr, ssKeyPtr) === 0, 'init_pull');
for (let i = 0; i < 3; i++) {
  const got = pullChunk(statePull, pushed[i].cPtr, pushed[i].clen, pushed[i].size);
  assert(got && got.text === chunks[i], `pull chunk ${i} text`);
  assert(got && got.tag === (i === 2 ? TAG_FINAL : TAG_MESSAGE), `pull chunk ${i} tag`);
}

const statePull2 = sodium._malloc(ssStatebytes);
assert(sodium._crypto_secretstream_xchacha20poly1305_init_pull(statePull2, ssHeaderPtr, ssKeyPtr) === 0, 'init_pull 2');
const skipped = pullChunk(statePull2, pushed[1].cPtr, pushed[1].clen, pushed[1].size);
assert(skipped === null, 'out-of-order chunk rejected');

const hexMax = 2 * keybytes + 1;
const hexPtr = sodium._malloc(hexMax);
sodium._sodium_bin2hex(hexPtr, hexMax, keyPtr, keybytes);
const keyHex = sodium.UTF8ToString(hexPtr);
assert(keyHex.length === 2 * keybytes, 'bin2hex length');

const keyCopy = sodium._malloc(keybytes);
const hexInPtr = sodium._malloc(keyHex.length + 1);
sodium.stringToUTF8(keyHex, hexInPtr, keyHex.length + 1);
const binRc = sodium._sodium_hex2bin(keyCopy, keybytes, hexInPtr, keyHex.length, 0, 0, 0);
assert(binRc === 0, 'hex2bin rc === 0');
let hexOk = true;
for (let i = 0; i < keybytes; i++) {
  if (sodium.HEAPU8[keyPtr + i] !== sodium.HEAPU8[keyCopy + i]) { hexOk = false; break; }
}
assert(hexOk, 'hex2bin roundtrip');

const VARIANT_ORIGINAL = 1;
const b64Max = sodium._sodium_base64_encoded_len(keybytes, VARIANT_ORIGINAL);
const b64Ptr = sodium._malloc(b64Max);
sodium._sodium_bin2base64(b64Ptr, b64Max, keyPtr, keybytes, VARIANT_ORIGINAL);
const keyB64 = sodium.UTF8ToString(b64Ptr);
const b64Copy = sodium._malloc(keybytes);
const b64rc = sodium._sodium_base642bin(b64Copy, keybytes, b64Ptr, keyB64.length, 0, 0, 0, VARIANT_ORIGINAL);
assert(b64rc === 0, 'base642bin rc === 0');
let b64Ok = true;
for (let i = 0; i < keybytes; i++) {
  if (sodium.HEAPU8[keyPtr + i] !== sodium.HEAPU8[b64Copy + i]) { b64Ok = false; break; }
}
assert(b64Ok, 'base64 roundtrip');

if (failed > 0) {
  console.error(`${failed} test(s) FAILED`);
  process.exit(1);
}
console.log('All tests passed.');
