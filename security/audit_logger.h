#ifndef AUDIT_LOGGER_H
#define AUDIT_LOGGER_H

typedef enum {
    OP_COMPRESS,
    OP_DECOMPRESS,
    OP_VALIDATE,
    OP_ACCESS_CHECK
} operation_t;

typedef enum {
    RESULT_SUCCESS,
    RESULT_FAILURE,
    RESULT_DENIED
} result_t;

void audit_log(operation_t op, const char *filepath, const char *hash, result_t result, const char *detail);

#endif
