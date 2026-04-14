#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

#include "session_gate.h"
#include "channel.h"



int session_check(session_t* s, packet_view_t* p)
{

    if(!s || !p || !p->buf)
    {
        return -1;
    }

    if (p->channel_id == CH_CONTROL && s->state != SESSION_LOCKED)
    {
        return 0;
    }

    if(s->state != SESSION_LOCKED)
    {
        return -1;
    }

    if (s->addr_len == 0)
        return -1;

    // session_id must match
    if (s->session_id != 0 && p->session_id != s->session_id)
        return -1;

    // address must match (strict)
    if (p->buf->addr_len != s->addr_len)
        return -1;

    struct sockaddr_in6* a = (struct sockaddr_in6*)p->buf->addr;
    struct sockaddr_in6* b = (struct sockaddr_in6*)s->addr;

    // family must match
    if (a->sin6_family != b->sin6_family)
        return -1;

    // port must match
    if (a->sin6_port != b->sin6_port)
        return -1;

    // compare ONLY raw IPv6 address bytes
    if (memcmp(a->sin6_addr.s6_addr,
            b->sin6_addr.s6_addr,
            16) != 0)
        return -1;    

    return 0;
}