

#ifdef _WIN32
#include <winsock2.h>

#include "io_poll.h"

#define MAX_SOCKS 64


int io_poll_init(io_poll_t* p)
{
    p->count = 0;
    return 0;
}

int io_poll_add(io_poll_t* p, udp_socket_t* s, int events)
{
    if (p->count >= MAX_SOCKS)
        return -1;

    p->socks[p->count] = s;
    p->events[p->count] = events;
    p->count++;

    return 0;
}

int io_poll_wait(io_poll_t* p, io_event_t* out, int max_events, int timeout_ms)
{
    fd_set readfds, writefds;

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    for (int i = 0; i < p->count; i++)
    {
        SOCKET fd = (SOCKET)p->socks[i]->fd;

        if (p->events[i] & IO_EVENT_READ)
            FD_SET(fd, &readfds);

        if (p->events[i] & IO_EVENT_WRITE)
            FD_SET(fd, &writefds);
    }

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int r = select(0, &readfds, &writefds, NULL, &tv);

    if (r <= 0)
        return r;

    int out_count = 0;

    for (int i = 0; i < p->count && out_count < max_events; i++)
    {
        SOCKET fd = (SOCKET)p->socks[i]->fd;

        int revents = 0;

        if (FD_ISSET(fd, &readfds))
            revents |= IO_EVENT_READ;

        if (FD_ISSET(fd, &writefds))
            revents |= IO_EVENT_WRITE;

        if (revents)
        {
            out[out_count].sock = p->socks[i];
            out[out_count].events = p->events[i];
            out[out_count].revents = revents;
            out_count++;
        }
    }

    return out_count;
}

void io_poll_destroy(io_poll_t* p)
{
    (void)p;
}

#endif