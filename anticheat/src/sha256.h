#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>

#define SHA256_DIGEST_LEN 32

typedef struct {
    unsigned char data[64];
    unsigned int datalen;
    unsigned long long bitlen;
    unsigned int state[8];
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len);
void sha256_final(sha256_ctx *ctx, unsigned char hash[SHA256_DIGEST_LEN]);
void sha256_memory(const void *data, size_t len,
                   unsigned char hash[SHA256_DIGEST_LEN]);

#endif
