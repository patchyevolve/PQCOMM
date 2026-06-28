#pragma once
#include "video_capture.h"
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
    video_capture_t capture;
    video_display_t display;
    volatile int running;
    volatile int active;
    int tx_seq;
    int rx_frame_count;
} video_worker_t;

int video_worker_start(video_worker_t* w, const char* device, int width_v, int height_v);
void video_worker_stop(video_worker_t* w);
int video_worker_tick(video_worker_t* w, session_t* sess, tx_queues_t* txq, rx_queues_t* rxq,
                      uint32_t* seq_counter, struct sockaddr_in6* peer_addr);
int video_worker_is_active(video_worker_t* w);
void video_worker_set_active(video_worker_t* w, int active);
