#pragma once
#include <stdint.h>

#define AUDIO_FRAME_MS    20
#define AUDIO_SAMPLE_RATE 48000
#define AUDIO_CHANNELS    1
#define AUDIO_FRAME_SAMPLES (AUDIO_SAMPLE_RATE * AUDIO_FRAME_MS / 1000)
#define AUDIO_FRAME_SIZE   (AUDIO_FRAME_SAMPLES * 2)
#define JITTER_MAX_MS     100
#define JITTER_MAX_FRAMES (JITTER_MAX_MS / AUDIO_FRAME_MS)

typedef struct {
    int16_t samples[AUDIO_FRAME_SAMPLES];
    uint64_t seq;
    uint64_t timestamp_ms;
} audio_frame_t;

typedef struct {
    audio_frame_t buffer[JITTER_MAX_FRAMES];
    uint32_t count;
    uint32_t read_cursor;
    uint32_t write_cursor;
    uint32_t target_frames;
} jitter_buffer_t;

typedef struct {
    void* encoder;
    void* decoder;
    jitter_buffer_t jitter;
    uint32_t packets_encoded;
    uint32_t packets_decoded;
    uint32_t packets_lost;
    uint32_t packets_late;
} audio_ctx_t;

int audio_init(audio_ctx_t* ctx);
int audio_encode(audio_ctx_t* ctx, const int16_t* pcm, uint32_t pcm_len,
                 uint8_t* out, uint32_t* out_len);
int audio_decode(audio_ctx_t* ctx, const uint8_t* data, uint32_t data_len,
                 int16_t* pcm, uint32_t* pcm_len);
void audio_destroy(audio_ctx_t* ctx);

void jitter_init(jitter_buffer_t* jb, uint32_t target_ms);
int jitter_push(jitter_buffer_t* jb, audio_frame_t* frame);
int jitter_pop(jitter_buffer_t* jb, audio_frame_t* frame);
void jitter_reset(jitter_buffer_t* jb);
