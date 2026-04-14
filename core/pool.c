#include "pool.h"

#include <stdlib.h>
#include "atomic.h"

static packet_buf_t* pool_mem = NULL;
static uint32_t free_stack[PACKET_POOL_SIZE];
static atomic_int_t top;

void pool_init(void)
{
    pool_mem = (packet_buf_t*)malloc(sizeof(packet_buf_t) * PACKET_POOL_SIZE);

    for (uint32_t i = 0; i < PACKET_POOL_SIZE; i++) {
        free_stack[i] = i;
    }

    atomic_store_int(&top, PACKET_POOL_SIZE);
}

packet_buf_t* pool_get(void)
{
    for (;;)
    {
        uint32_t t = atomic_load_int(&top);

        if (t == 0) {
            return NULL;
        }

        uint32_t new_t = t - 1;

        if (atomic_cas_int(&top, t, new_t))
        {
            uint32_t idx = free_stack[new_t];
            return &pool_mem[idx];
        }

    }
}

void pool_return(packet_buf_t* p) {
    uint32_t idx = (uint32_t)(p - pool_mem);

    for (;;)
    {
        uint32_t t = atomic_load_int(&top);

        if (t >= PACKET_POOL_SIZE)
            return;

        free_stack[t] = idx;

        if (atomic_cas_int(&top, t, t + 1))
        {
            return;
        }
    }
}

uint32_t pool_free_count(void) {
    return atomic_load_int(&top);
}

