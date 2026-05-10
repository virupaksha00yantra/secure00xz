#ifndef INTEGRITY_CHECKER_H
#define INTEGRITY_CHECKER_H

// Computes SHA-256 of file, writes hex string into out_hex (65 bytes min)
// Returns 0 on success, -1 on error
int compute_sha256(const char *filepath, char *out_hex);

// Saves hash to <filepath>.sha256 sidecar file
int save_hash(const char *filepath, const char *hex);

// Loads and verifies hash from sidecar file
// Returns 1 if match, 0 if mismatch, -1 if error
int verify_hash(const char *filepath);

#endif
