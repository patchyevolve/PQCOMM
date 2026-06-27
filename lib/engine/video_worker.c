#include "video_worker.h"
#include "packet.h"
#include "pool.h"
#include "session_enc.h"
#include "packet_parse.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int video_worker_start(video_worker_t* w, const char* device, int width_v, int height_v)
{
    if (!w) return -1;
    memset(w, 0, sizeof(*w));

    if (video_capture_init(&w->capture, device, width_v, height_v, VIDEO_FPS) != 0) return -1;
    if (video_display_init(&w->display, NULL, width_v, height_v) != 0) {
        video_capture_close(&w->capture);
        return -1;
    }

    w->running = 1;
    w->active = 0;
    w->tx_seq = 0;
    w->rx_frame_count = 0;
    return 0;
}

void video_worker_stop(video_worker_t* w)
{
    if (!w) return;
    w->running = 0;
    w->active = 0;
    video_display_close(&w->display);
    video_capture_close(&w->capture);
}

int video_worker_is_active(video_worker_t* w)
{
    return w && w->active;
}

void video_worker_set_active(video_worker_t* w, int active)
{
    if (w) w->active = active;
}

int video_worker_tick(video_worker_t* w, session_t* sess, tx_queues_t* txq, rx_queues_t* rxq,
                      uint32_t* seq_counter, struct sockaddr_in6* peer_addr)
{
    if (!w || !w->running) return -1;

    /* TX: capture → send */
    if (w->active) {
        uint8_t jpeg_buf[VIDEO_MAX_FRAME_SIZE];
        uint32_t jpeg_len = 0;
        if (video_capture_read_jpeg(&w->capture, jpeg_buf, &jpeg_len, sizeof(jpeg_buf)) == 0) {
            packet_buf_t* p = pool_get();
            if (p && jpeg_len > 0) {
                uint8_t* d = p->data;
                uint32_t magic = 0xAABBCCDD;
                uint8_t ver = 1, fl = 0, ch = CH_VIDEO;
                uint32_t seq = (*seq_counter)++;
                memcpy(d + 0, &magic, 4);
                memcpy(d + 4, &ver, 1);
                memcpy(d + 5, &fl, 1);
                memcpy(d + 6, &sess->session_id, 8);
                memcpy(d + 14, &ch, 1);
                memcpy(d + 15, &seq, 4);
                uint32_t payload_len = jpeg_len;
                memcpy(d + 19, &payload_len, 4);
                memcpy(d + 24, jpeg_buf, jpeg_len);
                p->len = 24 + payload_len;

                packet_view_t view = { 0 };
                if (packet_parse(p, &view) == 0)
                    session_enc_apply(p, &view, sess);

                if (peer_addr) {
                    memcpy(p->addr, peer_addr, sizeof(*peer_addr));
                    p->addr_len = sizeof(*peer_addr);
                }
                ring_push(&txq->video, p);
                w->tx_seq++;
            } else if (!p) {
                pool_return(p);
            }
        }
    }

    /* RX: receive → save frames */
    if (w->active) {
        packet_buf_t* p = (packet_buf_t*)ring_pop(&rxq->video);
        if (p) {
            packet_view_t view = { 0 };
            if (packet_parse(p, &view) == 0 && view.channel_id == CH_VIDEO) {
                video_display_show_jpeg(&w->display, view.payload, view.length,
                                        "/tmp/ssm_video", w->rx_frame_count);
                w->rx_frame_count++;
            }
            pool_return(p);
        }
    }

    return 0;
}
