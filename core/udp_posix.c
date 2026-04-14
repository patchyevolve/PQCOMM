
#ifndef _WIN32

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "udp.h"

int udp_socket_create(udp_socket_t* s, uint16_t port)
{
    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    // non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;

    // allow dual stack (IPv4 mapped)
    int v6only = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

    // buffers
    int buf = 8 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin6_family = AF_INET6;
    addr.sin6_port   = htons(port);
    addr.sin6_addr   = in6addr_any;

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }

    s->fd = fd;
    return 0;
}

int udp_socket_send(udp_socket_t* s,
                    const void* data,
                    uint32_t len,
                    const void* addr,
                    uint32_t addr_len)
{
    int r = sendto(s->fd, data, len, 0,
                   (const struct sockaddr*)addr,
                   addr_len);

    if (r < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -1; // no data, not fatal
        return -1;
    }
    return r;
}

int udp_socket_recv(udp_socket_t* s,
                    void* data,
                    uint32_t max_len,
                    void* addr,
                    uint32_t* addr_len)
{
    socklen_t alen = (socklen_t)*addr_len;

    int r = recvfrom(s->fd,
                     data,
                     max_len,
                     0,
                     (struct sockaddr*)addr,
                     &alen);

    if (r < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return -1; // no data, not fatal
        return -1;
    }

    *addr_len = (uint32_t)alen;
    return r;
}

void udp_socket_close(udp_socket_t* s)
{
    close(s->fd);
}

#endif