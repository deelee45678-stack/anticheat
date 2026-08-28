#define _GNU_SOURCE
#include "sha256.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void hex(const unsigned char *digest, char *out) {
    static const char *hexd = "0123456789abcdef";
    for (int i = 0; i < SHA256_DIGEST_LEN; i++) {
        out[i * 2] = hexd[(digest[i] >> 4) & 0xf];
        out[i * 2 + 1] = hexd[digest[i] & 0xf];
    }
    out[SHA256_DIGEST_LEN * 2] = '\0';
}

static void check(const char *label, const void *data, size_t len,
                  const char *expected) {
    unsigned char digest[SHA256_DIGEST_LEN];
    char got[SHA256_DIGEST_LEN * 2 + 1];

    sha256_memory(data, len, digest);
    hex(digest, got);

    if (strncmp(got, expected, SHA256_DIGEST_LEN * 2) != 0) {
        fprintf(stderr, "FAIL %s\n  expected %s\n  got      %s\n",
                label, expected, got);
        failures++;
    } else {
        printf("ok   %s\n", label);
    }
}

int main(void) {
    sha256_ctx ctx;
    unsigned char digest[SHA256_DIGEST_LEN];
    char got[SHA256_DIGEST_LEN * 2 + 1];

    /* FIPS 180-4 official test vectors. */
    check("sha256 empty string", "", 0,
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    check("sha256 \"abc\"", "abc", 3,
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const char *msg448 =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    check("sha256 448-bit message", msg448, 56,
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    const char *msg896 =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    check("sha256 896-bit message (112 bytes)", msg896, 112,
          "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");

    /* Incremental hashing must equal the one-shot result. */
    const char *incr = "the quick brown fox jumps over the lazy dog";
    sha256_init(&ctx);
    sha256_update(&ctx, (const unsigned char *)incr, 10);
    sha256_update(&ctx, (const unsigned char *)(incr + 10), strlen(incr) - 10);
    sha256_final(&ctx, digest);
    hex(digest, got);
    check("sha256 incremental == one-shot (\"the quick brown fox ...\")",
          incr, strlen(incr), got);

    if (failures) {
        fprintf(stderr, "\n%d test(s) failed\n", failures);
        return 1;
    }
    printf("\nall sha256 tests passed\n");
    return 0;
}
