
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "core.h"
#include "crypto_aead_chacha20poly1305.h"
#include "crypto_aead_xchacha20poly1305.h"
#include "crypto_core_hchacha20.h"
#include "crypto_onetimeauth_poly1305.h"
#include "crypto_stream_chacha20.h"
#include "crypto_verify_16.h"
#include "randombytes.h"
#include "utils.h"

#include "private/chacha20_ietf_ext.h"
#include "private/common.h"

static const unsigned char _pad0[16] = { 0 };

static int
_init_state(crypto_aead_xchacha20poly1305_ietf_state *state,
            const unsigned char *ad, unsigned long long adlen,
            const unsigned char *npub, const unsigned char *k)
{
    unsigned char block0[64U];
    unsigned char k2[crypto_core_hchacha20_OUTPUTBYTES];
    unsigned char npub2[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = { 0 };

    sodium_memzero(state, sizeof *state);

    crypto_core_hchacha20(k2, npub, k, NULL);
    memcpy(npub2 + 4, npub + crypto_core_hchacha20_INPUTBYTES,
           crypto_aead_chacha20poly1305_ietf_NPUBBYTES - 4);
    memcpy(state->k, k2, sizeof state->k);
    memcpy(state->npub, npub2, sizeof state->npub);
    sodium_memzero(k2, sizeof k2);

    crypto_stream_chacha20_ietf_ext(block0, sizeof block0, state->npub, state->k);
    crypto_onetimeauth_poly1305_init(&state->poly, block0);
    sodium_memzero(block0, sizeof block0);

    crypto_onetimeauth_poly1305_update(&state->poly, ad, adlen);
    crypto_onetimeauth_poly1305_update(&state->poly, _pad0, (0x10 - adlen) & 0xf);

    state->adlen  = adlen;
    state->mlen   = 0;
    state->ks_off = 64U;

    return 0;
}

static void
_xor_update(crypto_aead_xchacha20poly1305_ietf_state *state,
            unsigned char *out, const unsigned char *in, unsigned long long len)
{
    unsigned long long i = 0;
    uint32_t           ic;

    while (len > 0 && state->ks_off < 64U) {
        out[i] = in[i] ^ state->ks[state->ks_off];
        state->ks_off++;
        i++;
        len--;
        state->mlen++;
    }
    if (len == 0) {
        return;
    }

    ic = 1U + (uint32_t) (state->mlen / 64U);

    if (len >= 64U) {
        unsigned long long full = len & ~(unsigned long long) 63U;

        crypto_stream_chacha20_ietf_ext_xor_ic(out + i, in + i, full,
                                               state->npub, ic, state->k);
        state->mlen += full;
        i += full;
        len -= full;
        ic += (uint32_t) (full / 64U);
    }

    if (len > 0) {
        unsigned long long j;

        sodium_memzero(state->ks, sizeof state->ks);
        crypto_stream_chacha20_ietf_ext_xor_ic(state->ks, state->ks, 64U,
                                               state->npub, ic, state->k);
        for (j = 0; j < len; j++) {
            out[i + j] = in[i + j] ^ state->ks[j];
        }
        state->ks_off = (unsigned char) len;
        state->mlen += len;
    }
}

static int
_auth_final(crypto_aead_xchacha20poly1305_ietf_state *state, unsigned char *mac)
{
    unsigned char slen[8U];

    crypto_onetimeauth_poly1305_update(&state->poly, _pad0,
                                       (0x10 - state->mlen) & 0xf);

    STORE64_LE(slen, state->adlen);
    crypto_onetimeauth_poly1305_update(&state->poly, slen, sizeof slen);

    STORE64_LE(slen, state->mlen);
    crypto_onetimeauth_poly1305_update(&state->poly, slen, sizeof slen);

    crypto_onetimeauth_poly1305_final(&state->poly, mac);
    return 0;
}

size_t
crypto_aead_xchacha20poly1305_ietf_statebytes(void)
{
    return sizeof(crypto_aead_xchacha20poly1305_ietf_state);
}

int
crypto_aead_xchacha20poly1305_ietf_encrypt_init(
    crypto_aead_xchacha20poly1305_ietf_state *state,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, const unsigned char *k)
{
    return _init_state(state, ad, adlen, npub, k);
}

int
crypto_aead_xchacha20poly1305_ietf_encrypt_update(
    crypto_aead_xchacha20poly1305_ietf_state *state,
    unsigned char *c, const unsigned char *m, unsigned long long mlen)
{
    if (mlen > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX - state->mlen) {
        sodium_misuse();
    }
    if (mlen == 0) {
        return 0;
    }
    _xor_update(state, c, m, mlen);
    crypto_onetimeauth_poly1305_update(&state->poly, c, mlen);
    return 0;
}

int
crypto_aead_xchacha20poly1305_ietf_encrypt_final(
    crypto_aead_xchacha20poly1305_ietf_state *state, unsigned char *mac)
{
    _auth_final(state, mac);
    sodium_memzero(state, sizeof *state);
    return 0;
}

int
crypto_aead_xchacha20poly1305_ietf_decrypt_init(
    crypto_aead_xchacha20poly1305_ietf_state *state,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, const unsigned char *k)
{
    return _init_state(state, ad, adlen, npub, k);
}

int
crypto_aead_xchacha20poly1305_ietf_decrypt_update(
    crypto_aead_xchacha20poly1305_ietf_state *state,
    unsigned char *m, const unsigned char *c, unsigned long long clen)
{
    if (clen > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX - state->mlen) {
        sodium_misuse();
    }
    if (clen == 0) {
        return 0;
    }
    /* Authenticate ciphertext before XOR so in-place decrypt (m == c) is safe. */
    crypto_onetimeauth_poly1305_update(&state->poly, c, clen);
    _xor_update(state, m, c, clen);
    return 0;
}

int
crypto_aead_xchacha20poly1305_ietf_decrypt_final(
    crypto_aead_xchacha20poly1305_ietf_state *state, const unsigned char *mac)
{
    unsigned char computed_mac[crypto_aead_xchacha20poly1305_ietf_ABYTES];
    int           ret;

    _auth_final(state, computed_mac);
    COMPILER_ASSERT(sizeof computed_mac == 16U);
    ret = crypto_verify_16(computed_mac, mac);
    sodium_memzero(computed_mac, sizeof computed_mac);
    sodium_memzero(state, sizeof *state);
    return ret;
}

int
crypto_aead_xchacha20poly1305_ietf_encrypt_detached(unsigned char *c,
                                                    unsigned char *mac,
                                                    unsigned long long *maclen_p,
                                                    const unsigned char *m,
                                                    unsigned long long mlen,
                                                    const unsigned char *ad,
                                                    unsigned long long adlen,
                                                    const unsigned char *nsec,
                                                    const unsigned char *npub,
                                                    const unsigned char *k)
{
    crypto_aead_xchacha20poly1305_ietf_state state;
    int                                      ret;

    (void) nsec;
    ret = crypto_aead_xchacha20poly1305_ietf_encrypt_init(&state, ad, adlen, npub, k);
    if (ret != 0) {
        return ret;
    }
    ret = crypto_aead_xchacha20poly1305_ietf_encrypt_update(&state, c, m, mlen);
    if (ret != 0) {
        sodium_memzero(&state, sizeof state);
        return ret;
    }
    ret = crypto_aead_xchacha20poly1305_ietf_encrypt_final(&state, mac);
    if (maclen_p != NULL) {
        *maclen_p = crypto_aead_xchacha20poly1305_ietf_ABYTES;
    }
    return ret;
}

int
crypto_aead_xchacha20poly1305_ietf_encrypt(unsigned char *c,
                                           unsigned long long *clen_p,
                                           const unsigned char *m,
                                           unsigned long long mlen,
                                           const unsigned char *ad,
                                           unsigned long long adlen,
                                           const unsigned char *nsec,
                                           const unsigned char *npub,
                                           const unsigned char *k)
{
    unsigned long long clen = 0ULL;
    int                ret;

    if (mlen > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX) {
        sodium_misuse();
    }
    ret = crypto_aead_xchacha20poly1305_ietf_encrypt_detached
        (c, c + mlen, NULL, m, mlen, ad, adlen, nsec, npub, k);
    if (clen_p != NULL) {
        if (ret == 0) {
            clen = mlen + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        }
        *clen_p = clen;
    }
    return ret;
}

int
crypto_aead_xchacha20poly1305_ietf_decrypt_detached(unsigned char *m,
                                                    unsigned char *nsec,
                                                    const unsigned char *c,
                                                    unsigned long long clen,
                                                    const unsigned char *mac,
                                                    const unsigned char *ad,
                                                    unsigned long long adlen,
                                                    const unsigned char *npub,
                                                    const unsigned char *k)
{
    crypto_onetimeauth_poly1305_state state;
    unsigned char                     block0[64U];
    unsigned char                     slen[8U];
    unsigned char                     computed_mac[crypto_aead_chacha20poly1305_ietf_ABYTES];
    unsigned char                     k2[crypto_core_hchacha20_OUTPUTBYTES];
    unsigned char                     npub2[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = { 0 };
    unsigned long long                mlen;
    int                               ret;

    (void) nsec;
    crypto_core_hchacha20(k2, npub, k, NULL);
    memcpy(npub2 + 4, npub + crypto_core_hchacha20_INPUTBYTES,
           crypto_aead_chacha20poly1305_ietf_NPUBBYTES - 4);

    crypto_stream_chacha20_ietf_ext(block0, sizeof block0, npub2, k2);
    crypto_onetimeauth_poly1305_init(&state, block0);
    sodium_memzero(block0, sizeof block0);

    crypto_onetimeauth_poly1305_update(&state, ad, adlen);
    crypto_onetimeauth_poly1305_update(&state, _pad0, (0x10 - adlen) & 0xf);

    mlen = clen;
    crypto_onetimeauth_poly1305_update(&state, c, mlen);
    crypto_onetimeauth_poly1305_update(&state, _pad0, (0x10 - mlen) & 0xf);

    STORE64_LE(slen, (uint64_t) adlen);
    crypto_onetimeauth_poly1305_update(&state, slen, sizeof slen);

    STORE64_LE(slen, (uint64_t) mlen);
    crypto_onetimeauth_poly1305_update(&state, slen, sizeof slen);

    crypto_onetimeauth_poly1305_final(&state, computed_mac);
    sodium_memzero(&state, sizeof state);

    COMPILER_ASSERT(sizeof computed_mac == 16U);
    ret = crypto_verify_16(computed_mac, mac);
    sodium_memzero(computed_mac, sizeof computed_mac);
    if (m == NULL) {
        sodium_memzero(k2, sizeof k2);
        return ret;
    }
    if (ret != 0) {
        memset(m, 0, mlen);
        sodium_memzero(k2, sizeof k2);
        return -1;
    }
    crypto_stream_chacha20_ietf_ext_xor_ic(m, c, mlen, npub2, 1U, k2);
    sodium_memzero(k2, sizeof k2);

    return 0;
}

int
crypto_aead_xchacha20poly1305_ietf_decrypt(unsigned char *m,
                                           unsigned long long *mlen_p,
                                           unsigned char *nsec,
                                           const unsigned char *c,
                                           unsigned long long clen,
                                           const unsigned char *ad,
                                           unsigned long long adlen,
                                           const unsigned char *npub,
                                           const unsigned char *k)
{
    unsigned long long mlen = 0ULL;
    int                ret  = -1;

    if (clen >= crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        ret = crypto_aead_xchacha20poly1305_ietf_decrypt_detached
            (m, nsec,
             c, clen - crypto_aead_xchacha20poly1305_ietf_ABYTES,
             c + clen - crypto_aead_xchacha20poly1305_ietf_ABYTES,
             ad, adlen, npub, k);
    }
    if (mlen_p != NULL) {
        if (ret == 0) {
            mlen = clen - crypto_aead_xchacha20poly1305_ietf_ABYTES;
        }
        *mlen_p = mlen;
    }
    return ret;
}

size_t
crypto_aead_xchacha20poly1305_ietf_keybytes(void)
{
    return crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
}

size_t
crypto_aead_xchacha20poly1305_ietf_npubbytes(void)
{
    return crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
}

size_t
crypto_aead_xchacha20poly1305_ietf_nsecbytes(void)
{
    return crypto_aead_xchacha20poly1305_ietf_NSECBYTES;
}

size_t
crypto_aead_xchacha20poly1305_ietf_abytes(void)
{
    return crypto_aead_xchacha20poly1305_ietf_ABYTES;
}

size_t
crypto_aead_xchacha20poly1305_ietf_messagebytes_max(void)
{
    return crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX;
}

void
crypto_aead_xchacha20poly1305_ietf_keygen(unsigned char k[crypto_aead_xchacha20poly1305_ietf_KEYBYTES])
{
    randombytes_buf(k, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}
