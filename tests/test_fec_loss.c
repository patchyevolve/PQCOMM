#include <string.h>
#include "resilience_ctx.h"

int test_fec_recovery(void)
{
    resilience_t r;
    resilience_init(&r);
    r.fec_group_size = 4;

    uint8_t data[4][16];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 16; j++)
            data[i][j] = (uint8_t)(i * 16 + j);

    uint8_t parity[FEC_MAX_PAYLOAD];
    uint32_t parity_len;
    int group_complete;

    for (uint32_t seq = 100; seq < 104; seq++) {
        fec_tx_accumulate(&r, data[seq - 100], 16, seq, 1, 3,
                          parity, &parity_len, &group_complete);
    }
    if (!group_complete) return -1;
    if (parity_len != 6 + 16) return -2;

    /* RX side: feed only 3 of 4 packets (skip seq 102), store parity, rebuild */
    resilience_t rx;
    resilience_init(&rx);
    rx.fec_group_size = 4;

    fec_rx_track(&rx, 100, data[0], 16);
    fec_rx_track(&rx, 101, data[1], 16);
    fec_rx_track(&rx, 103, data[3], 16);
    fec_rx_store_parity(&rx, parity, parity_len);

    uint8_t recovered[FEC_MAX_PAYLOAD];
    uint32_t recovered_len;
    uint32_t recovered_seq;
    int ret = fec_rx_rebuild(&rx, recovered, &recovered_len, &recovered_seq);
    if (ret != 1) return -3;
    if (recovered_seq != 102) return -4;
    if (recovered_len != 16) return -5;
    if (memcmp(recovered, data[2], 16) != 0) return -6;

    return 0;
}

int test_fec_no_recovery_all_present(void)
{
    resilience_t r;
    resilience_init(&r);
    r.fec_group_size = 4;

    uint8_t data[4][16];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 16; j++)
            data[i][j] = (uint8_t)(i * 16 + j);

    uint8_t parity[FEC_MAX_PAYLOAD];
    uint32_t parity_len;
    int group_complete;

    for (uint32_t seq = 200; seq < 204; seq++) {
        fec_tx_accumulate(&r, data[seq - 200], 16, seq, 1, 3,
                          parity, &parity_len, &group_complete);
    }
    if (!group_complete) return -1;

    /* RX: all 4 packets present, parity stored — rebuild should return 0 (no recovery needed) */
    resilience_t rx;
    resilience_init(&rx);
    rx.fec_group_size = 4;

    fec_rx_track(&rx, 200, data[0], 16);
    fec_rx_track(&rx, 201, data[1], 16);
    fec_rx_track(&rx, 202, data[2], 16);
    fec_rx_track(&rx, 203, data[3], 16);
    fec_rx_store_parity(&rx, parity, parity_len);

    uint8_t recovered[FEC_MAX_PAYLOAD];
    uint32_t recovered_len;
    uint32_t recovered_seq;
    int ret = fec_rx_rebuild(&rx, recovered, &recovered_len, &recovered_seq);
    if (ret != 0) return -2;

    return 0;
}
