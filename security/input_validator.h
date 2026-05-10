#ifndef INPUT_VALIDATOR_H
#define INPUT_VALIDATOR_H

#define MAX_FILE_SIZE_MB 512

typedef enum {
    VALID_OK = 0,
    VALID_ERR_NULL,
    VALID_ERR_PATH_TRAVERSAL,
    VALID_ERR_NULL_BYTE,
    VALID_ERR_TOO_LARGE,
    VALID_ERR_BAD_EXTENSION,
    VALID_ERR_NOT_FOUND
} validation_result_t;

validation_result_t validate_input_file(const char *path, int is_compress);
const char *validation_error_str(validation_result_t r);

#endif
