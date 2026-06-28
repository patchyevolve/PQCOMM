#include "lan_discovery.h"
#include "udp.h"
#include "connection_manager.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

#define DISCOVERY_MAGIC 0xDEADBEEF
#define DISCOVERY_VERSION 1

static udp_socket_t g_disc_sock;
static int g_initialized = 0;
static int g_running = 0;
static uint16_t g_local_transport_port = 0;
static uint16_t g_discovery_port = 0;
static char g_local_username[32] = "";

static int g_broadcast_sock = -1;

uint16_t lan_discovery_get_port(void) { return g_discovery_port; }

int lan_discovery_init(uint16_t disc_port, uint16_t transport_port)
{
    if (g_initialized) return -1;
    g_discovery_port = disc_port;
    g_local_transport_port = transport_port;

    if (udp_socket_create(&g_disc_sock, disc_port) != 0) {
        printf("[DISCOVERY] failed to bind on port %u\n", disc_port);
        return -1;
    }

    g_broadcast_sock = (int)socket(AF_INET, SOCK_DGRAM, 0);
    if (g_broadcast_sock < 0) {
        udp_socket_close(&g_disc_sock);
        return -1;
    }
    int broadcast_enable = 1;
    setsockopt(g_broadcast_sock, SOL_SOCKET, SO_BROADCAST,
               (const char*)&broadcast_enable, sizeof(broadcast_enable));

    g_initialized = 1;
    return 0;
}

void lan_discovery_shutdown(void)
{
    g_running = 0;
    g_initialized = 0;
    udp_socket_close(&g_disc_sock);
    if (g_broadcast_sock >= 0) {
        close(g_broadcast_sock);
        g_broadcast_sock = -1;
    }
}

int lan_discovery_start(void)
{
    if (!g_initialized) return -1;
    g_running = 1;
    return 0;
}

void lan_discovery_stop(void)
{
    g_running = 0;
}

void lan_discovery_set_username(const char* username)
{
    if (username)
        snprintf(g_local_username, sizeof(g_local_username), "%s", username);
}

static void send_beacon(void)
{
    if (g_broadcast_sock < 0) return;

    uint32_t uname_len = (uint32_t)strlen(g_local_username);
    if (uname_len > 31) uname_len = 31;
    uint32_t msg_len = 4 + 1 + 2 + 1 + uname_len;

    uint8_t msg[64];
    uint32_t magic = DISCOVERY_MAGIC;
    uint8_t ver = DISCOVERY_VERSION;
    uint16_t port = g_local_transport_port;

    memcpy(msg + 0, &magic, 4);
    memcpy(msg + 4, &ver, 1);
    memcpy(msg + 5, &port, 2);
    msg[7] = (uint8_t)uname_len;
    if (uname_len > 0) memcpy(msg + 8, g_local_username, uname_len);

    struct sockaddr_in bc_addr;
    memset(&bc_addr, 0, sizeof(bc_addr));
    bc_addr.sin_family = AF_INET;
    bc_addr.sin_port = htons(g_discovery_port);
    bc_addr.sin_addr.s_addr = INADDR_BROADCAST;

    sendto(g_broadcast_sock, (const char*)msg, msg_len, 0,
           (const struct sockaddr*)&bc_addr, sizeof(bc_addr));
}

static int try_recv_beacon(void)
{
    uint8_t buf[64];
    struct sockaddr_in6 from_addr;
    uint32_t from_len = sizeof(from_addr);
    memset(&from_addr, 0, sizeof(from_addr));

    int ret = udp_socket_recv(&g_disc_sock, buf, sizeof(buf),
                               &from_addr, &from_len);
    if (ret <= 0) return 0;

    if (ret < 8) return 0;

    uint32_t magic;
    uint8_t ver;
    uint16_t port;
    memcpy(&magic, buf + 0, 4);
    memcpy(&ver, buf + 4, 1);
    memcpy(&port, buf + 5, 2);

    if (magic != DISCOVERY_MAGIC || ver != DISCOVERY_VERSION) return 0;

    uint8_t uname_len = buf[7];
    if (uname_len > 31) uname_len = 31;

    char username[32] = "";
    if (uname_len > 0 && ret >= 8 + uname_len)
        memcpy(username, buf + 8, uname_len);

    char addr_str[64];
    addr_str[0] = '\0';
    if (from_addr.sin6_family == AF_INET6) {
        inet_ntop(AF_INET6, &from_addr.sin6_addr, addr_str, sizeof(addr_str));
    } else if (from_addr.sin6_family == AF_INET) {
        struct sockaddr_in* v4 = (struct sockaddr_in*)&from_addr;
        inet_ntop(AF_INET, &v4->sin_addr, addr_str, sizeof(addr_str));
    }
    if (addr_str[0] == '\0') return 1;

    /* skip self-broadcast echo */
    if (strcmp(addr_str, "::1") == 0 || strcmp(addr_str, "127.0.0.1") == 0)
        return 1;

    peer_t* existing = NULL;
    int count = 0;
    peer_t* peers = connection_manager_get_peers(&count);
    for (int i = 0; i < count; i++) {
        if (strcmp(peers[i].addr_str, addr_str) == 0 && peers[i].port == port) {
            existing = &peers[i];
            break;
        }
    }
    uint64_t now_ms = (uint64_t)time(NULL) * 1000;
    if (!existing) {
        connection_manager_connect(addr_str, port);
    }
    if (username[0])
        connection_manager_set_username(addr_str, port, username);
    connection_manager_update_last_seen(addr_str, port, now_ms);
    return 1;
}

void lan_discovery_trigger_scan(void)
{
    send_beacon();
    for (int i = 0; i < 10; i++) {
        if (try_recv_beacon() == 0) break;
    }
}
