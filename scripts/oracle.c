/* Test-only wrapper around pinned Nano sources. Never installed or used by NOMS. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <crypto/ed25519-donna/ed25519.h>
#include <crypto/ed25519-donna/ed25519-hash-custom.h>

void ed25519_randombytes_unsafe(void *out, size_t len) {
    /* Deterministic test randomness; this wrapper never handles real keys. */
    memset(out, 0x42, len);
}
void ed25519_hash_init(ed25519_hash_context *ctx) { blake2b_init(ctx, 64); }
void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t len) { blake2b_update(ctx, in, len); }
void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *out) { blake2b_final(ctx, out, 64); }
void ed25519_hash(uint8_t *out, const uint8_t *in, size_t len) {
    ed25519_hash_context ctx;
    ed25519_hash_init(&ctx); ed25519_hash_update(&ctx, in, len); ed25519_hash_final(&ctx, out);
}
static int nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
static size_t unhex(const char *text, uint8_t *out, size_t max) {
    size_t len = strlen(text);
    if (len % 2 || len / 2 > max) exit(2);
    for (size_t i = 0; i < len / 2; i++) {
        int a = nibble(text[i*2]), b = nibble(text[i*2+1]);
        if (a < 0 || b < 0) exit(2);
        out[i] = (uint8_t)((a << 4) | b);
    }
    return len / 2;
}
int main(void) {
    char operation[16], message_hex[16385], signature_hex[129], key_hex[65];
    uint8_t message[8192], signature[64], key[32], digest[32], public_key[32];
    while (scanf("%15s %16384s", operation, message_hex) == 2) {
        size_t len = strcmp(message_hex, "-") == 0 ? 0 : unhex(message_hex, message, sizeof(message));
        if (strcmp(operation, "hash") == 0) {
            blake2b(digest, 32, message, len, NULL, 0);
            for (size_t i = 0; i < 32; i++) printf("%02x", digest[i]);
            puts("");
        } else if (strcmp(operation, "verify") == 0) {
            if (scanf("%128s %64s", signature_hex, key_hex) != 2) return 2;
            if (unhex(signature_hex, signature, sizeof(signature)) != 64 || unhex(key_hex, key, sizeof(key)) != 32) return 2;
            puts(ed25519_sign_open(message, len, key, signature) == 0 ? "valid" : "invalid");
        } else if (strcmp(operation, "sign") == 0) {
            if (scanf("%64s", key_hex) != 1 || unhex(key_hex, key, sizeof(key)) != 32) return 2;
            ed25519_publickey(key, public_key);
            ed25519_sign(message, len, key, public_key, signature);
            for (size_t i = 0; i < 64; i++) printf("%02x", signature[i]);
            puts("");
        } else return 2;
    }
    return ferror(stdin) ? 2 : 0;
}
