#ifndef crypto_aead_xchacha20poly1305_H
#define crypto_aead_xchacha20poly1305_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_onetimeauth_poly1305.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_aead_xchacha20poly1305_ietf_KEYBYTES 32U
SODIUM_EXPORT
size_t crypto_aead_xchacha20poly1305_ietf_keybytes(void);

#define crypto_aead_xchacha20poly1305_ietf_NSECBYTES 0U
SODIUM_EXPORT
size_t crypto_aead_xchacha20poly1305_ietf_nsecbytes(void);

#define crypto_aead_xchacha20poly1305_ietf_NPUBBYTES 24U
SODIUM_EXPORT
size_t crypto_aead_xchacha20poly1305_ietf_npubbytes(void);

#define crypto_aead_xchacha20poly1305_ietf_ABYTES 16U
SODIUM_EXPORT
size_t crypto_aead_xchacha20poly1305_ietf_abytes(void);

#define crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX \
    (SODIUM_SIZE_MAX - crypto_aead_xchacha20poly1305_ietf_ABYTES)
SODIUM_EXPORT
size_t crypto_aead_xchacha20poly1305_ietf_messagebytes_max(void);

SODIUM_EXPORT
int crypto_aead_xchacha20poly1305_ietf_encrypt(unsigned char *c,
                                               unsigned long long *clen_p,
                                               const unsigned char *m,
                                               unsigned long long mlen,
                                               const unsigned char *ad,
                                               unsigned long long adlen,
                                               const unsigned char *nsec,
                                               const unsigned char *npub,
                                               const unsigned char *k)
            __attribute__ ((nonnull(1, 8, 9)));

SODIUM_EXPORT
int crypto_aead_xchacha20poly1305_ietf_decrypt(unsigned char *m,
                                               unsigned long long *mlen_p,
                                               unsigned char *nsec,
                                               const unsigned char *c,
                                               unsigned long long clen,
                                               const unsigned char *ad,
                                               unsigned long long adlen,
                                               const unsigned char *npub,
                                               const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(4, 8, 9)));

SODIUM_EXPORT
int crypto_aead_xchacha20poly1305_ietf_encrypt_detached(unsigned char *c,
                                                        unsigned char *mac,
                                                        unsigned long long *maclen_p,
                                                        const unsigned char *m,
                                                        unsigned long long mlen,
                                                        const unsigned char *ad,
                                                        unsigned long long adlen,
                                                        const unsigned char *nsec,
                                                        const unsigned char *npub,
                                                        const unsigned char *k)
            __attribute__ ((nonnull(1, 2, 9, 10)));

SODIUM_EXPORT
int crypto_aead_xchacha20poly1305_ietf_decrypt_detached(unsigned char *m,
                                                        unsigned char *nsec,
                                                        const unsigned char *c,
                                                        unsigned long long clen,
                                                        const unsigned char *mac,
                                                        const unsigned char *ad,
                                                        unsigned long long adlen,
                                                        const unsigned char *npub,
                                                        const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5, 8, 9)));

SODIUM_EXPORT
void crypto_aead_xchacha20poly1305_ietf_keygen(unsigned char k[crypto_aead_xchacha20poly1305_ietf_KEYBYTES])
            __attribute__ ((nonnull));

/*
 * Incremental API producing the same ciphertext and single 16-byte tag as the
 * one-shot IETF functions above. AD is supplied only in *_init.
 *
 * Decrypt is decrypt-then-verify: plaintext from *_decrypt_update is written
 * before the tag is checked in *_decrypt_final. On forgery, prior plaintext
 * chunks may already have been exposed to the caller; *_decrypt_final returns
 * -1 and wipes the state, but cannot recall previously returned plaintext.
 */

typedef struct CRYPTO_ALIGN(16) crypto_aead_xchacha20poly1305_ietf_state {
    crypto_onetimeauth_poly1305_state poly;
    unsigned char                     k[32];
    unsigned char                     npub[12];
    unsigned char                     ks[64];
    unsigned char                     ks_off; /* next unused byte in ks; 64 = empty */
    unsigned char                     _pad[7];
    uint64_t                          adlen;
    uint64_t                          mlen;
} crypto_aead_xchacha20poly1305_ietf_state;

SODIUM_EXPORT
size_t crypto_aead_xchacha20poly1305_ietf_statebytes(void);

SODIUM_EXPORT
int crypto_aead_xchacha20poly1305_ietf_encrypt_init(
    crypto_aead_xchacha20poly1305_ietf_state *state,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, const unsigned char *k)
            __attribute__ ((nonnull(1, 4, 5)));

SODIUM_EXPORT
int crypto_aead_xchacha20poly1305_ietf_encrypt_update(
    crypto_aead_xchacha20poly1305_ietf_state *state,
    unsigned char *c, const unsigned char *m, unsigned long long mlen)
            __attribute__ ((nonnull(1)));

SODIUM_EXPORT
int crypto_aead_xchacha20poly1305_ietf_encrypt_final(
    crypto_aead_xchacha20poly1305_ietf_state *state, unsigned char *mac)
            __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_aead_xchacha20poly1305_ietf_decrypt_init(
    crypto_aead_xchacha20poly1305_ietf_state *state,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, const unsigned char *k)
            __attribute__ ((nonnull(1, 4, 5)));

SODIUM_EXPORT
int crypto_aead_xchacha20poly1305_ietf_decrypt_update(
    crypto_aead_xchacha20poly1305_ietf_state *state,
    unsigned char *m, const unsigned char *c, unsigned long long clen)
            __attribute__ ((nonnull(1)));

SODIUM_EXPORT
int crypto_aead_xchacha20poly1305_ietf_decrypt_final(
    crypto_aead_xchacha20poly1305_ietf_state *state, const unsigned char *mac)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

/* Aliases */

#define crypto_aead_xchacha20poly1305_IETF_KEYBYTES         crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define crypto_aead_xchacha20poly1305_IETF_NSECBYTES        crypto_aead_xchacha20poly1305_ietf_NSECBYTES
#define crypto_aead_xchacha20poly1305_IETF_NPUBBYTES        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define crypto_aead_xchacha20poly1305_IETF_ABYTES           crypto_aead_xchacha20poly1305_ietf_ABYTES
#define crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX

#ifdef __cplusplus
}
#endif

#endif
