#include "adaptive_bitrate.h"

int test_abr_off(void)
{
    abr_ctx_t ctx;
    abr_init(&ctx);

    resilience_t res;
    resilience_init(&res);
    res.fec_enabled = 1;
    res.fec_group_size = 4;

    /* 0% loss — ABR should disable FEC */
    int ret = abr_update(&ctx, &res, 10000);
    if (ret != 1) return -1;
    if (res.fec_enabled != 0) return -2;
    if (res.fec_group_size != 0) return -3;

    return 0;
}

int test_abr_low_loss(void)
{
    abr_ctx_t ctx;
    abr_init(&ctx);

    resilience_t res;
    resilience_init(&res);
    res.fec_enabled = 0;
    res.fec_group_size = 0;

    /* Simulate ~5% loss: record losses in window */
    for (int i = 0; i < 64; i++) {
        if (i % 20 == 0)
            resilience_record_loss(&res, 0);
        else
            resilience_record_rx(&res, 0, 1000);
    }

    /* Trigger ABR update */
    int ret = abr_update(&ctx, &res, 10000);
    if (ret != 1) return -1;
    if (res.fec_enabled != 1) return -2;
    if (res.fec_group_size != 8) return -3;

    return 0;
}

int test_abr_high_loss(void)
{
    abr_ctx_t ctx;
    abr_init(&ctx);

    resilience_t res;
    resilience_init(&res);
    res.fec_enabled = 0;
    res.fec_group_size = 0;

    /* Simulate ~25% loss */
    for (int i = 0; i < 64; i++) {
        if (i % 4 == 0)
            resilience_record_loss(&res, 0);
        else
            resilience_record_rx(&res, 0, 1000);
    }

    int ret = abr_update(&ctx, &res, 10000);
    if (ret != 1) return -1;
    if (res.fec_enabled != 1) return -2;
    if (res.fec_group_size != 2) return -3;

    return 0;
}
