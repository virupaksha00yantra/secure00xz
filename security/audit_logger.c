#include "audit_logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>

static const char *op_str(operation_t op) {
    switch(op) {
        case OP_COMPRESS:     return "COMPRESS";
        case OP_DECOMPRESS:   return "DECOMPRESS";
        case OP_VALIDATE:     return "VALIDATE";
        case OP_ACCESS_CHECK: return "ACCESS_CHECK";
        default:              return "UNKNOWN";
    }
}

static const char *res_str(result_t r) {
    switch(r) {
        case RESULT_SUCCESS: return "SUCCESS";
        case RESULT_FAILURE: return "FAILURE";
        case RESULT_DENIED:  return "DENIED";
        default:             return "UNKNOWN";
    }
}

void audit_log(operation_t op, const char *filepath, const char *hash, result_t result, const char *detail) {
    char log_path[512];
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        home = pw ? pw->pw_dir : "/tmp";
    }
    snprintf(log_path, sizeof(log_path), "%s/.xz_audit.log", home);

    FILE *f = fopen(log_path, "a");
    if (!f) return;

    time_t now = time(NULL);
    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", localtime(&now));

    uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    const char *username = pw ? pw->pw_name : "unknown";

    fprintf(f, "[%s] user=%s op=%s file=%s hash=%s result=%s detail=%s\n",
        tbuf, username, op_str(op),
        filepath ? filepath : "N/A",
        hash     ? hash     : "N/A",
        res_str(result),
        detail   ? detail   : "");

    fclose(f);
}
