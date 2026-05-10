#include "access_control.h"
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

const char *ac_error_str(ac_result_t r) {
    switch(r) {
        case AC_OK:                return "Access OK";
        case AC_ERR_STAT:          return "Cannot stat file";
        case AC_ERR_WORLD_WRITABLE:return "File is world-writable (unsafe)";
        case AC_ERR_SUID_SGID:     return "File has SUID/SGID bit set (suspicious)";
        case AC_ERR_NO_READ:       return "No read permission";
        case AC_ERR_SYMLINK:       return "Symlink detected (potential TOCTOU risk)";
        default:                   return "Unknown";
    }
}

ac_result_t check_file_access(const char *filepath) {
    struct stat lst, st;

    // Symlink check (lstat vs stat)
    if (lstat(filepath, &lst) != 0) return AC_ERR_STAT;
    if (S_ISLNK(lst.st_mode))       return AC_ERR_SYMLINK;

    if (stat(filepath, &st) != 0)   return AC_ERR_STAT;

    // World-writable check
    if (st.st_mode & S_IWOTH)        return AC_ERR_WORLD_WRITABLE;

    // SUID/SGID check
    if (st.st_mode & (S_ISUID | S_ISGID)) return AC_ERR_SUID_SGID;

    // Read permission check
    if (access(filepath, R_OK) != 0) return AC_ERR_NO_READ;

    return AC_OK;
}
