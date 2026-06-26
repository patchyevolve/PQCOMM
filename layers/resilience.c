#include "resilience.h"
#include "channel.h"
#include <string.h>

int resilience_check(packet_view_t* p, session_t* sess)
{
    if (!p || !sess) return -1;
    if (sess->state != SESSION_LOCKED) return 0;

    uint32_t path_idx = 0;
    resilience_record_rx(&sess->resilience, path_idx, 0);

    return 0;
}
