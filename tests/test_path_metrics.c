#include "resilience_ctx.h"

int test_path_loss_window(void)
{
    resilience_t r;
    resilience_init(&r);

    /* Fill all 64 slots: 32 losses + 32 receives = exactly 50% */
    for (int i = 0; i < 32; i++)
        resilience_record_loss(&r, 0);
    for (int i = 0; i < 32; i++)
        resilience_record_rx(&r, 0, 1000);

    /* loss_rate should be 32/64 = 0.5 */
    if (r.paths[0].packets_lost != 32) return -1;
    if (r.paths[0].packets_recv != 32) return -2;
    if (r.paths[0].loss_rate < 0.49f || r.paths[0].loss_rate > 0.51f) return -3;

    /* Fill window with successes (64 more receives) */
    for (int i = 0; i < 64; i++)
        resilience_record_rx(&r, 0, 1000);

    if (r.paths[0].loss_rate != 0.0f) return -4;

    return 0;
}

int test_path_state_transition(void)
{
    resilience_t r;
    resilience_init(&r);
    r.heartbeat_interval_ms = 1000;
    r.reconnect_timeout_ms = 5000;

    /* ACTIVE after first RX (last_activity_ms must be set for tick to work) */
    r.paths[0].last_activity_ms = 100000;

    if (r.paths[0].state != PATH_UNKNOWN) return -1;

    /* RX makes it ACTIVE and sets last_activity_ms */
    resilience_record_rx(&r, 0, 1000);
    if (r.paths[0].state != PATH_ACTIVE) return -2;

    /* No activity for 3s → DEGRADED */
    int changed = resilience_tick(&r, 100000 + 3001);
    if (!changed) return -3;
    if (r.paths[0].state != PATH_DEGRADED) return -4;

    /* No activity for reconnect_timeout → DOWN */
    changed = resilience_tick(&r, 100000 + 3001 + 5001);
    if (!changed) return -5;
    if (r.paths[0].state != PATH_DOWN) return -6;

    /* RX restores to ACTIVE */
    resilience_record_rx(&r, 0, 1000);
    if (r.paths[0].state != PATH_ACTIVE) return -7;

    return 0;
}

int test_path_select(void)
{
    resilience_t r;
    resilience_init(&r);

    uint32_t sel = resilience_select_path(&r);
    if (sel != 0) return -1;

    r.multipath_enabled = 1;
    r.path_count = 2;

    /* Path 1 has lower loss */
    r.paths[0].loss_rate = 0.5f;
    r.paths[0].state = PATH_ACTIVE;
    r.paths[1].loss_rate = 0.1f;
    r.paths[1].state = PATH_ACTIVE;

    sel = resilience_select_path(&r);
    if (sel != 1) return -2;

    /* Path 1 goes DOWN → fall back to 0 */
    r.paths[1].state = PATH_DOWN;
    sel = resilience_select_path(&r);
    if (sel != 0) return -3;

    return 0;
}
