#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "io_wait.h"

int io_wait_read(udp_socket_t* s, int timeout_ms)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET((SOCKET)s->fd, &fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int r = select(0, &fds, NULL, NULL, &tv);
    return (r <= 0) ? -1 : 0;
}

int io_wait_write(udp_socket_t* s, int timeout_ms)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET((SOCKET)s->fd, &fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int r = select(0, NULL, &fds, NULL, &tv);
    return (r <= 0) ? -1 : 0;
}

#endif