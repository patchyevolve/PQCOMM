#pragma once

#include <stdint.h>
#include <stdlib.h>
#include "atomic.h"
#include "config.h"

/* spsc ring - no locks, no allocs, power-of-2 only */

typedef struct 
{
    void* slots[RING_SIZE];

    atomic_int_t write_idx;
    atomic_int_t read_idx;

} spsc_ring_t;

static inline
void ring_init(spsc_ring_t* r)
{
    atomic_store_int(&r->write_idx, 0);
    atomic_store_int(&r->read_idx, 0);
}

static inline
int ring_push(spsc_ring_t* r, void* item)
{
    uint32_t w = atomic_load_int(&r->write_idx);

    uint32_t next = (w+1) & (RING_SIZE - 1);

    uint32_t rd = atomic_load_int(&r->read_idx);

    if (next == rd)
        return -1;

    r->slots[w] = item;

    atomic_store_int(&r->write_idx, next);
    
    return 0;
}

static inline
void* ring_pop(spsc_ring_t* r)
{
    uint32_t rd = atomic_load_int(&r->read_idx);

    uint32_t w = atomic_load_int( &r->write_idx );

    if (rd == w)
        return NULL;

    void* item = r->slots[rd];

    uint32_t next = (rd+1) & (RING_SIZE - 1);

    atomic_store_int(&r->read_idx, next);

    return item;

}