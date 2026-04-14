#pragma once

#include "udp.h"

int io_wait_read(udp_socket_t* s, int timeout_ms);

int io_wait_write(udp_socket_t* s, int timeout_ms);


