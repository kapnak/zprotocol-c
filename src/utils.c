#include "utils.h"

/**
 * Equivalent of `recv` with `MSG_WAITALL` flag.
 *
 * It seems that the cygwin version of `recv` result in an infinite loop
 * when the socket is closed properly and return 0. This issue needs to
 * be verified. But for now this patch is working well.
 * Version: CYGWIN_NT-10.0-22631 x 3.5.1-1.x86_64 2024-02-27 11:54 UTC x86_64 Cygwin
 * OS: Windows 11 version 23H2 build 22631.3447
 *
 * @param fd
 * @param buf
 * @param len
 * @param flags
 * @return
 */
ssize_t recv_waitall(int fd, void *buf, size_t len, int flags) {
    ssize_t bytes_recv = 0;
    while (bytes_recv < len) {
        ssize_t res = recv(fd, buf + bytes_recv, len - bytes_recv, flags);
        if (res <= 0)
            return res;
        bytes_recv += res;
    }
    return bytes_recv;
}
