#pragma once
#include <stdint.h>

typedef enum
{
    CH_CONTROL = 1,
    CH_AUDIO   = 2,
    CH_CHAT    = 3,
    CH_FILE    = 4,
    CH_ROUTE   = 5,
    CH_VIDEO   = 6

} channel_id_t;