#pragma once
#include "resilience_ctx.h"
#include <stdint.h>

#define ABR_UPDATE_INTERVAL_MS 3000
#define ABR_LOSS_LOW_THRESH  0.03f
#define ABR_LOSS_MED_THRESH  0.10f
#define ABR_LOSS_HIGH_THRESH 0.20f
#define ABR_GROUP_LOW      8
#define ABR_GROUP_MED      4
#define ABR_GROUP_HIGH     2

typedef struct {
    uint8_t current_fec_group_size;
    uint8_t fec_was_enabled;
    uint8_t abr_enabled;
    uint64_t last_update_ms;
    float current_loss_rate;
} abr_ctx_t;

void abr_init(abr_ctx_t* ctx);
int abr_update(abr_ctx_t* ctx, resilience_t* res, uint64_t now_ms);
