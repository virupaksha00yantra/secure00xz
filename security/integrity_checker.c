#include "integrity_checker.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int compute_sha256(const char *filepath, char *out_hex) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return -1; }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx); fclose(f); return -1;
    }

    unsigned char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        EVP_DigestUpdate(ctx, buf, n);
    fclose(f);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < digest_len; i++)
        sprintf(out_hex + i*2, "%02x", digest[i]);
    out_hex[digest_len * 2] = '\0';
    return 0;
}

int save_hash(const char *filepath, const char *hex) {
    char sidecar[512];
    snprintf(sidecar, sizeof(sidecar), "%s.sha256", filepath);
    FILE *f = fopen(sidecar, "w");
    if (!f) return -1;
    fprintf(f, "%s  %s\n", hex, filepath);
    fclose(f);
    return 0;
}

int verify_hash(const char *filepath) {
    char sidecar[512];
    snprintf(sidecar, sizeof(sidecar), "%s.sha256", filepath);

    FILE *f = fopen(sidecar, "r");
    if (!f) return -1;

    char stored[65];
    if (fscanf(f, "%64s", stored) != 1) { fclose(f); return -1; }
    fclose(f);

    char actual[65];
    if (compute_sha256(filepath, actual) != 0) return -1;

    return strcmp(stored, actual) == 0 ? 1 : 0;
}
