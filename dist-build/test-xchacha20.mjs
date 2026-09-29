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
assert(sodium._sodium_library_minimal() === 1, 'library_minimal');

const keybytes = sodium._crypto_aead_xchacha20poly1305_ietf_keybytes();
const nsecbytes = sodium._crypto_aead_xchacha20poly1305_ietf_nsecbytes();
const npubbytes = sodium._crypto_aead_xchacha20poly1305_ietf_npubbytes();
const abytes = sodium._crypto_aead_xchacha20poly1305_ietf_abytes();
const maxbytes = sodium._crypto_aead_xchacha20poly1305_ietf_messagebytes_max();
const statebytes = sodium._crypto_aead_xchacha20poly1305_ietf_statebytes();

assert(keybytes === 32, 'keybytes === 32');
assert(nsecbytes === 0, 'nsecbytes === 0');
assert(npubbytes === 24, 'npubbytes === 24');
assert(abytes === 16, 'abytes === 16');
assert(statebytes > 0, 'statebytes > 0');
const sizemax = 4294967295;
const expectedMax = sizemax - abytes;
assert(
  maxbytes === expectedMax || maxbytes === expectedMax - 2 ** 32,
  'messagebytes_max === SIZE_MAX - abytes'
);

// Forbidden APIs must not be exported from this trimmed build.
assert(typeof sodium._crypto_secretstream_xchacha20poly1305_push === 'undefined',
  'secretstream not exported');
assert(typeof sodium._crypto_aead_chacha20poly1305_ietf_encrypt === 'undefined',
  'chacha20poly1305 not exported');

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

// --- streaming AEAD (single tag, matches one-shot) ---
const streamPlain = new TextEncoder().encode(
  'stream chunk A · stream chunk B · final bytes 0123456789'
);
const streamMsgPtr = sodium._malloc(streamPlain.length);
sodium.HEAPU8.set(streamPlain, streamMsgPtr);

const oneShotCtPtr = sodium._malloc(streamPlain.length);
const oneShotMacPtr = sodium._malloc(abytes);
rc = sodium._crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
  oneShotCtPtr, oneShotMacPtr, mdlenPtr, streamMsgPtr, BigInt(streamPlain.length),
  0, 0n, 0, npubPtr, keyPtr
);
assert(rc === 0, 'oneshot encrypt for stream compare');

const streamCtPtr = sodium._malloc(streamPlain.length);
const streamMacPtr = sodium._malloc(abytes);
const encState = sodium._malloc(statebytes);
assert(
  sodium._crypto_aead_xchacha20poly1305_ietf_encrypt_init(encState, 0, 0n, npubPtr, keyPtr) === 0,
  'aead encrypt_init'
);
const streamChunks = [1, 7, 16, 33, 64, 20];
let soff = 0;
let si = 0;
while (soff < streamPlain.length) {
  let n = streamChunks[si % streamChunks.length];
  if (n > streamPlain.length - soff) n = streamPlain.length - soff;
  rc = sodium._crypto_aead_xchacha20poly1305_ietf_encrypt_update(
    encState, streamCtPtr + soff, streamMsgPtr + soff, BigInt(n)
  );
  assert(rc === 0, `aead encrypt_update chunk ${si}`);
  soff += n;
  si++;
}
assert(
  sodium._crypto_aead_xchacha20poly1305_ietf_encrypt_final(encState, streamMacPtr) === 0,
  'aead encrypt_final'
);
let streamCtOk = true;
for (let i = 0; i < streamPlain.length; i++) {
  if (sodium.HEAPU8[oneShotCtPtr + i] !== sodium.HEAPU8[streamCtPtr + i]) {
    streamCtOk = false;
    break;
  }
}
assert(streamCtOk, 'stream ciphertext === oneshot ciphertext');
let streamMacOk = true;
for (let i = 0; i < abytes; i++) {
  if (sodium.HEAPU8[oneShotMacPtr + i] !== sodium.HEAPU8[streamMacPtr + i]) {
    streamMacOk = false;
    break;
  }
}
assert(streamMacOk, 'stream mac === oneshot mac');

const streamDecPtr = sodium._malloc(streamPlain.length);
const decState = sodium._malloc(statebytes);
assert(
  sodium._crypto_aead_xchacha20poly1305_ietf_decrypt_init(decState, 0, 0n, npubPtr, keyPtr) === 0,
  'aead decrypt_init'
);
soff = 0;
si = 0;
while (soff < streamPlain.length) {
  let n = streamChunks[(si + 2) % streamChunks.length];
  if (n > streamPlain.length - soff) n = streamPlain.length - soff;
  rc = sodium._crypto_aead_xchacha20poly1305_ietf_decrypt_update(
    decState, streamDecPtr + soff, streamCtPtr + soff, BigInt(n)
  );
  assert(rc === 0, `aead decrypt_update chunk ${si}`);
  soff += n;
  si++;
}
assert(
  sodium._crypto_aead_xchacha20poly1305_ietf_decrypt_final(decState, streamMacPtr) === 0,
  'aead decrypt_final'
);
assert(
  new TextDecoder().decode(sodium.HEAPU8.subarray(streamDecPtr, streamDecPtr + streamPlain.length)) ===
    new TextDecoder().decode(streamPlain),
  'stream decrypt roundtrip'
);

assert(
  sodium._crypto_aead_xchacha20poly1305_ietf_decrypt_init(decState, 0, 0n, npubPtr, keyPtr) === 0,
  'aead decrypt_init bad mac'
);
rc = sodium._crypto_aead_xchacha20poly1305_ietf_decrypt_update(
  decState, streamDecPtr, streamCtPtr, BigInt(streamPlain.length)
);
assert(rc === 0, 'aead decrypt_update before bad mac');
sodium.HEAPU8[streamMacPtr] ^= 1;
assert(
  sodium._crypto_aead_xchacha20poly1305_ietf_decrypt_final(decState, streamMacPtr) === -1,
  'aead decrypt_final rejects bad mac'
);
sodium.HEAPU8[streamMacPtr] ^= 1;

assert(
  sodium._crypto_aead_xchacha20poly1305_ietf_encrypt_init(encState, 0, 0n, npubPtr, keyPtr) === 0,
  'empty encrypt_init'
);
assert(
  sodium._crypto_aead_xchacha20poly1305_ietf_encrypt_final(encState, streamMacPtr) === 0,
  'empty encrypt_final'
);
rc = sodium._crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
  oneShotCtPtr, oneShotMacPtr, mdlenPtr, streamMsgPtr, 0n, 0, 0n, 0, npubPtr, keyPtr
);
assert(rc === 0, 'empty oneshot encrypt');
streamMacOk = true;
for (let i = 0; i < abytes; i++) {
  if (sodium.HEAPU8[oneShotMacPtr + i] !== sodium.HEAPU8[streamMacPtr + i]) {
    streamMacOk = false;
    break;
  }
}
assert(streamMacOk, 'empty stream mac === oneshot mac');

if (failed > 0) {
  console.error(`${failed} test(s) FAILED`);
  process.exit(1);
}
console.log('All tests passed.');
