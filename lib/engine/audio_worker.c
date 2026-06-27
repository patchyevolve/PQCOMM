#include "audio_worker.h"
#include "packet.h"
#include "pool.h"
#include "session_enc.h"
#include "packet_parse.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>

int audio_worker_start(audio_worker_t* w, const char* device)
{
    if (!w) return -1;
    memset(w, 0, sizeof(*w));

    if (audio_init(&w->codec) != 0) return -1;
    if (audio_capture_init(&w->capture, device) != 0) { audio_destroy(&w->codec); return -1; }
    if (audio_playback_init(&w->playback, device) != 0) { audio_capture_close(&w->capture); audio_destroy(&w->codec); return -1; }

    w->running = 1;
    w->active = 0;
    w->tx_seq = 0;
    return 0;
}

void audio_worker_stop(audio_worker_t* w)
{
    if (!w) return;
    w->running = 0;
    w->active = 0;
    audio_playback_close(&w->playback);
    audio_capture_close(&w->capture);
    audio_destroy(&w->codec);
}

int audio_worker_is_active(audio_worker_t* w)
{
    return w && w->active;
}

void audio_worker_set_active(audio_worker_t* w, int active)
{
    if (w) w->active = active;
}

int audio_worker_tick(audio_worker_t* w, session_t* sess, tx_queues_t* txq, rx_queues_t* rxq,
                      uint32_t* seq_counter, struct sockaddr_in6* peer_addr)
{
    if (!w || !w->running) return -1;

    /* TX: capture → encode → send */
    if (w->active) {
        int16_t pcm[AUDIO_FRAME_SAMPLES];
        if (audio_capture_read(&w->capture, pcm, AUDIO_FRAME_SAMPLES) == 0) {
            uint8_t enc[512];
            uint32_t enc_len = sizeof(enc);
            if (audio_encode(&w->codec, pcm, AUDIO_FRAME_SAMPLES, enc, &enc_len) == 0 && enc_len > 0) {
                packet_buf_t* p = pool_get();
                if (p) {
                    uint8_t* d = p->data;
                    uint32_t magic = 0xAABBCCDD;
                    uint8_t ver = 1, fl = 0, ch = CH_AUDIO;
                    uint32_t seq = (*seq_counter)++;
                    memcpy(d + 0, &magic, 4);
                    memcpy(d + 4, &ver, 1);
                    memcpy(d + 5, &fl, 1);
                    memcpy(d + 6, &sess->session_id, 8);
                    memcpy(d + 14, &ch, 1);
                    memcpy(d + 15, &seq, 4);
                    memcpy(d + 19, &enc_len, 4);
                    memcpy(d + 24, enc, enc_len);
                    p->len = 24 + enc_len;

                    packet_view_t view = { 0 };
                    if (packet_parse(p, &view) == 0)
                        session_enc_apply(p, &view, sess);

                    if (peer_addr) {
                        memcpy(p->addr, peer_addr, sizeof(*peer_addr));
                        p->addr_len = sizeof(*peer_addr);
                    }
                    ring_push(&txq->audio, p);
                    w->tx_seq++;
                }
            }
        }
    }

    /* RX: receive → decode → playback */
    if (w->active) {
        packet_buf_t* p = (packet_buf_t*)ring_pop(&rxq->audio);
        if (p) {
            packet_view_t view = { 0 };
            if (packet_parse(p, &view) == 0 && view.channel_id == CH_AUDIO) {
                int16_t pcm[AUDIO_FRAME_SAMPLES];
                uint32_t pcm_len = AUDIO_FRAME_SAMPLES;
                if (audio_decode(&w->codec, view.payload, view.length,
                                 pcm, &pcm_len) == 0 && pcm_len > 0) {
                    audio_playback_write(&w->playback, pcm, pcm_len);
                }
            }
            pool_return(p);
        }
    }

    return 0;
}
