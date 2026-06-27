#pragma once

#ifdef _WIN32
#include <Windows.h>
typedef volatile long atomic_int_t;

static inline void atomic_store_int(atomic_int_t* v, int x)
{
    InterlockedExchange(v, x);
}
static inline int atomic_load_int(atomic_int_t* v)
{
    return InterlockedCompareExchange(v, 0, 0);
}
static inline int atomic_fetch_add_int(atomic_int_t* v, int x)
{
    return InterlockedExchangeAdd(v, x);
}
static inline int atomic_cas_int(atomic_int_t* v, int expected, int desired)
{
    return InterlockedCompareExchange(v, desired, expected) == expected;
}
#else
#include <stdatomic.h>
typedef atomic_int atomic_int_t;

static inline void atomic_store_int(atomic_int_t* v, int x)
{
    atomic_store(v, x);
}
static inline int atomic_load_int(atomic_int_t* v)
{
    return atomic_load(v);
}
static inline int atomic_fetch_add_int(atomic_int_t* v, int x)
{
    return atomic_fetch_add(v, x);
}
static inline int atomic_cas_int(atomic_int_t* v, int expected, int desired)
{
    return atomic_compare_exchange_strong(v, &expected, desired);
}
#endif