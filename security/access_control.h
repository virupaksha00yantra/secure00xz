#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

typedef enum {
    AC_OK = 0,
    AC_ERR_STAT,
    AC_ERR_WORLD_WRITABLE,
    AC_ERR_SUID_SGID,
    AC_ERR_NO_READ,
    AC_ERR_SYMLINK
} ac_result_t;

ac_result_t check_file_access(const char *filepath);
const char *ac_error_str(ac_result_t r);

#endif
