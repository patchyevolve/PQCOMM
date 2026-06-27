#pragma once
#include <stdint.h>
#include "audio_pipeline.h"

/* PCM capture/playback via arecord/aplay subprocess pipes */

#define AUDIO_PCM_SAMPLE_RATE 48000
#define AUDIO_PCM_CHANNELS 1
#define AUDIO_PCM_FORMAT "S16_LE"
/* AUDIO_FRAME_SAMPLES from audio_pipeline.h (960) */
#define AUDIO_FRAME_BYTES (AUDIO_FRAME_SAMPLES * 2) /* 16-bit */

typedef struct {
    void* pipe;
    int active;
    char device[64];
} audio_capture_t;

typedef struct {
    void* pipe;
    int active;
    char device[64];
} audio_playback_t;

int audio_capture_init(audio_capture_t* cap, const char* device);
void audio_capture_close(audio_capture_t* cap);
int audio_capture_read(audio_capture_t* cap, int16_t* samples, uint32_t frame_samples);

int audio_playback_init(audio_playback_t* play, const char* device);
void audio_playback_close(audio_playback_t* play);
int audio_playback_write(audio_playback_t* play, const int16_t* samples, uint32_t frame_samples);
