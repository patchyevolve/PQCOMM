#include "udp.h"
#include "pool.h"
#include "ring.h"
#include "config.h"
#include "packet.h"

int udp_rx_once(udp_socket_t* s, spsc_ring_t* rx_ring)
{
    packet_buf_t* p = pool_get();
    if (!p)
        return -1;

    uint32_t addr_len = sizeof(p->addr);
    int r = udp_socket_recv(s, p->data, MAX_PACKET_SIZE, p->addr, &addr_len);

    if (r < 0) {
        pool_return(p);
        return -1;
    }

    p->len = (uint32_t)r;
    p->addr_len = addr_len;

    if (ring_push(rx_ring, p) != 0) {
        pool_return(p);
        return -1;
    }
    return 0;
}

int udp_tx_once(udp_socket_t* s, spsc_ring_t* tx_ring)
{
    packet_buf_t* p = (packet_buf_t*)ring_pop(tx_ring);
    if (!p) return -1;

    int r = udp_socket_send(s, p->data, p->len, p->addr, p->addr_len);
    if (r < 0) {
        pool_return(p);
        return -1;
    }

    pool_return(p);
    return 0;
}
