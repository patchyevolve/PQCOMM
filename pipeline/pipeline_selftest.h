#pragma once

#include "ring.h"
#include "session.h"

void pipeline_enqueue_phase1_selftests(spsc_ring_t* rx_ring);

void pipeline_enqueue_seq_duplicate_probe(spsc_ring_t* rx_ring, session_t* sess);
