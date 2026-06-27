#ifndef _WIN32

#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include "io_wait.h"

int io_wait_read(udp_socket_t* s, int timeout_ms)
{
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(s->fd, &fds);

    struct timeval tv;

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int r = select(s->fd + 1, &fds, NULL, NULL, &tv);

    if (r <= 0)
        return -1;

    return 0;
}

int io_wait_write(udp_socket_t* s, int timeout_ms)
{
    fd_set fds;

    FD_ZERO(&fds);
    FD_SET(s->fd, &fds);

    struct timeval tv;

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int r = select(s->fd + 1, NULL, &fds, NULL, &tv);

    if (r <= 0)
        return -1;

    return 0;
}

#endif