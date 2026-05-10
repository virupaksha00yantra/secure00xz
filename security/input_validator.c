#include "input_validator.h"
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>

const char *validation_error_str(validation_result_t r) {
    switch(r) {
        case VALID_OK:                return "OK";
        case VALID_ERR_NULL:          return "Null path";
        case VALID_ERR_PATH_TRAVERSAL:return "Path traversal detected";
        case VALID_ERR_NULL_BYTE:     return "Null byte in path";
        case VALID_ERR_TOO_LARGE:     return "File exceeds size limit";
        case VALID_ERR_BAD_EXTENSION: return "Unexpected file extension";
        case VALID_ERR_NOT_FOUND:     return "File not found";
        default:                      return "Unknown error";
    }
}

validation_result_t validate_input_file(const char *path, int is_compress) {
    if (!path) return VALID_ERR_NULL;

    // Null byte check
    size_t len = strlen(path);
    for (size_t i = 0; i < len; i++)
        if (path[i] == '\0') return VALID_ERR_NULL_BYTE;

    // Path traversal check
    if (strstr(path, "../") || strstr(path, "..\\"))
        return VALID_ERR_PATH_TRAVERSAL;

    // Extension check
    const char *ext = strrchr(path, '.');
    if (is_compress) {
        // compressing: should NOT be .xz already
        if (ext && strcmp(ext, ".xz") == 0)
            return VALID_ERR_BAD_EXTENSION;
    } else {
        // decompressing: must be .xz or .lzma
        if (!ext || (strcmp(ext, ".xz") != 0 && strcmp(ext, ".lzma") != 0))
            return VALID_ERR_BAD_EXTENSION;
    }

    // File existence + size check
    struct stat st;
    if (stat(path, &st) != 0) return VALID_ERR_NOT_FOUND;
    if (st.st_size > (long)(MAX_FILE_SIZE_MB * 1024 * 1024))
        return VALID_ERR_TOO_LARGE;

    return VALID_OK;
}
