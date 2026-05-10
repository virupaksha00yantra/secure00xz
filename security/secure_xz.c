#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "input_validator.h"
#include "integrity_checker.h"
#include "access_control.h"
#include "audit_logger.h"

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: secure_xz [compress|decompress] <file>\n");
        return 1;
    }

    int is_compress = (strcmp(argv[1], "compress") == 0);
    const char *filepath = argv[2];

    // 1. Input Validation
    validation_result_t vr = validate_input_file(filepath, is_compress);
    if (vr != VALID_OK) {
        fprintf(stderr, "[SECURITY] Input validation failed: %s\n", validation_error_str(vr));
        audit_log(OP_VALIDATE, filepath, NULL, RESULT_DENIED, validation_error_str(vr));
        return 2;
    }
    audit_log(OP_VALIDATE, filepath, NULL, RESULT_SUCCESS, "Input validation passed");

    // 2. Access Control
    ac_result_t ar = check_file_access(filepath);
    if (ar != AC_OK) {
        fprintf(stderr, "[SECURITY] Access control denied: %s\n", ac_error_str(ar));
        audit_log(OP_ACCESS_CHECK, filepath, NULL, RESULT_DENIED, ac_error_str(ar));
        return 3;
    }
    audit_log(OP_ACCESS_CHECK, filepath, NULL, RESULT_SUCCESS, "Access control passed");

    // 3. Integrity: hash before operation
    char hash_before[65];
    if (compute_sha256(filepath, hash_before) == 0) {
        if (is_compress) save_hash(filepath, hash_before);
        audit_log(is_compress ? OP_COMPRESS : OP_DECOMPRESS,
                  filepath, hash_before, RESULT_SUCCESS, "Pre-op hash computed");
    }

    // 4. Call real xz
    char cmd[1024];
    if (is_compress)
        snprintf(cmd, sizeof(cmd), "xz -k \"%s\"", filepath);
    else
        snprintf(cmd, sizeof(cmd), "xz -dk \"%s\"", filepath);

    int ret = system(cmd);

    // 5. Post-op audit
    result_t final = (ret == 0) ? RESULT_SUCCESS : RESULT_FAILURE;
    audit_log(is_compress ? OP_COMPRESS : OP_DECOMPRESS,
              filepath, hash_before, final,
              ret == 0 ? "xz completed OK" : "xz returned error");

    if (ret != 0) {
        fprintf(stderr, "[SECURITY] xz operation failed (exit %d)\n", ret);
        return 4;
    }

    printf("[SECURITY] Operation completed. Audit log updated.\n");
    return 0;
}
