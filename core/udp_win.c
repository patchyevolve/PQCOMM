
#ifdef _WIN32

#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "udp.h"

#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

static int wsa_initialized = 0;

static int udp_wsa_init(void)
{
    if (wsa_initialized)
        return 0;

    WSADATA d;

    if (WSAStartup(MAKEWORD(2, 2), &d) != 0) {
        return -1;
    }

    wsa_initialized = 1;

    return 0;
}

int udp_socket_create(udp_socket_t* s, uint16_t port)
{
    if (udp_wsa_init() != 0) {
        return -1;
    }

    SOCKET fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    if (fd == INVALID_SOCKET)
        return -1;

    u_long nonblock = 1;

    ioctlsocket(fd, FIONBIO, &nonblock);

    int v6only = 0;

    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&v6only, sizeof(v6only));

    int buf = 8 * 1024 * 1024;

    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&buf, sizeof(buf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&buf, sizeof(buf));

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;


    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        closesocket(fd);
        return -1;
    }

    s->fd = (udp_fd_t)fd;

    return 0;
}

int udp_socket_send(udp_socket_t* s, const void* data, uint32_t len, const void* addr, uint32_t addr_len)
{
    int r = sendto((SOCKET)s->fd, (const char*)data, (int)len, 0, (const struct sockaddr*)addr, (int)addr_len);
    
    if (r == SOCKET_ERROR) {
        int err = WSAGetLastError();
        (void)err;
        return -1;
    }
    return r;
}

int udp_socket_recv(udp_socket_t* s, void* data, uint32_t max_len, void* addr, uint32_t* addr_len)
{
    int alen = (int)*addr_len;
    
    int r = recvfrom((SOCKET)s->fd, (char*)data, (int)max_len, 0, (struct sockaddr*)addr, &alen);

    if (r == SOCKET_ERROR) {
        int err = WSAGetLastError();

        if (err == WSAEWOULDBLOCK)
            return -1; // no data available

        return -1; // real error
    }

    *addr_len = (uint32_t)alen;

    return r;
}

void udp_socket_close(udp_socket_t* s) {
    closesocket((SOCKET)s->fd);
}

#endif
