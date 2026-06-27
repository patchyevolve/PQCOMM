#include "lan_discovery.h"
#include <stdio.h>

static int g_discovery_running = 0;

int lan_discovery_init(uint16_t port)
{
    (void)port;
    return 0;
}

void lan_discovery_shutdown(void)
{
    g_discovery_running = 0;
}

int lan_discovery_start(void)
{
    g_discovery_running = 1;
    return 0;
}

void lan_discovery_stop(void)
{
    g_discovery_running = 0;
}

void lan_discovery_trigger_scan(void)
{
}
