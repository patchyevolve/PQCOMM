#include "channel_enc.h"
#include "channel.h"

/* channel-level encryption stub: available for future use */
int channel_enc_check(packet_view_t* p, session_t* sess)
{
    (void)p;
    (void)sess;
    return 0;
}

int channel_enc_apply(packet_buf_t* p, packet_view_t* view, session_t* sess)
{
    (void)p;
    (void)view;
    (void)sess;
    return 0;
}
