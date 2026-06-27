#include "adaptive_bitrate.h"
#include <stdio.h>

void abr_init(abr_ctx_t* ctx)
{
    if (!ctx) return;
    ctx->current_fec_group_size = 4;
    ctx->fec_was_enabled = 1;
    ctx->abr_enabled = 1;
    ctx->last_update_ms = 0;
    ctx->current_loss_rate = 0.0f;
}

int abr_update(abr_ctx_t* ctx, resilience_t* res, uint64_t now_ms)
{
    if (!ctx || !res || !ctx->abr_enabled) return 0;
    if (now_ms - ctx->last_update_ms < ABR_UPDATE_INTERVAL_MS) return 0;
    ctx->last_update_ms = now_ms;

    float max_loss = 0.0f;
    for (uint32_t i = 0; i < res->path_count; i++) {
        if (res->paths[i].loss_rate > max_loss)
            max_loss = res->paths[i].loss_rate;
    }
    ctx->current_loss_rate = max_loss;

    uint8_t new_group = ctx->current_fec_group_size;
    uint8_t new_fec_enabled = res->fec_enabled;

    if (max_loss < ABR_LOSS_LOW_THRESH) {
        new_fec_enabled = 0;
        new_group = 0;
    } else if (max_loss < ABR_LOSS_MED_THRESH) {
        new_fec_enabled = 1;
        new_group = ABR_GROUP_LOW;
    } else if (max_loss < ABR_LOSS_HIGH_THRESH) {
        new_fec_enabled = 1;
        new_group = ABR_GROUP_MED;
    } else {
        new_fec_enabled = 1;
        new_group = ABR_GROUP_HIGH;
    }

    if (new_fec_enabled != res->fec_enabled || new_group != res->fec_group_size) {
        uint8_t old_fec = res->fec_enabled;
        uint8_t old_group = res->fec_group_size;
        res->fec_enabled = new_fec_enabled;
        res->fec_group_size = new_group;
        printf("[ABR] loss=%.1f%% fec=%s group=%u -> %s group=%u\n",
               max_loss * 100.0f,
               old_fec ? "on" : "off", old_group,
               new_fec_enabled ? "on" : "off", new_group);
        ctx->current_fec_group_size = new_group;
        ctx->fec_was_enabled = new_fec_enabled;
        return 1;
    }

    return 0;
}
