#pragma once
#include "audio_pipeline.h"
#include "audio_capture.h"
#include "scheduler.h"
#include "rx_demux.h"
#include "session.h"
#include "channel.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

typedef struct {
    audio_ctx_t codec;
    audio_capture_t capture;
    audio_playback_t playback;
    int running;
    int active; /* call active flag */
    int tx_seq;
} audio_worker_t;

int audio_worker_start(audio_worker_t* w, const char* device);
void audio_worker_stop(audio_worker_t* w);
int audio_worker_tick(audio_worker_t* w, session_t* sess, tx_queues_t* txq, rx_queues_t* rxq,
                      uint32_t* seq_counter, struct sockaddr_in6* peer_addr);
int audio_worker_is_active(audio_worker_t* w);
void audio_worker_set_active(audio_worker_t* w, int active);
