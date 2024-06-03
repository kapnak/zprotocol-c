#ifndef ZPROTOCOL_UTILS_H
#define ZPROTOCOL_UTILS_H

#include <stdio.h>
#include <netinet/in.h>

// For cygwin
#if __CYGWIN__
#define RECV_ALL(fd, buf, len, flag) recv_waitall(fd, buf, len, flag)
#else
#define RECV_ALL(fd, buf, len, flag) recv(fd, buf, len, flag | MSG_WAITALL)
#endif

ssize_t recv_waitall(int fd, void *buf, size_t len, int flags);

#endif