#include "audio_pipeline.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

int test_audio_encode_decode(void)
{
    audio_ctx_t ctx;
    if (audio_init(&ctx) != 0) {
        printf("[FAIL] audio_init failed\n");
        return -1;
    }

    int16_t pcm_in[AUDIO_FRAME_SAMPLES];
    int16_t pcm_out[AUDIO_FRAME_SAMPLES];
    uint8_t encoded[4096];
    uint32_t enc_len = sizeof(encoded);
    uint32_t dec_len = AUDIO_FRAME_SAMPLES * 2;

    for (int i = 0; i < AUDIO_FRAME_SAMPLES; i++)
        pcm_in[i] = (int16_t)(sinf((float)i * 0.01f) * 8000.0f);

    if (audio_encode(&ctx, pcm_in, AUDIO_FRAME_SAMPLES, encoded, &enc_len) != 0) {
        printf("[FAIL] audio_encode failed\n");
        audio_destroy(&ctx);
        return -1;
    }
    if (enc_len == 0 || enc_len >= sizeof(encoded)) {
        printf("[FAIL] audio_encode bad length %u\n", enc_len);
        audio_destroy(&ctx);
        return -1;
    }

    if (audio_decode(&ctx, encoded, enc_len, pcm_out, &dec_len) != 0) {
        printf("[FAIL] audio_decode failed\n");
        audio_destroy(&ctx);
        return -1;
    }
    if (dec_len != AUDIO_FRAME_SAMPLES) {
        printf("[FAIL] audio_decode bad sample count %u\n", dec_len);
        audio_destroy(&ctx);
        return -1;
    }

    float energy = 0.0f;
    for (int i = 0; i < AUDIO_FRAME_SAMPLES; i++)
        energy += (float)(pcm_out[i]) * (float)(pcm_out[i]);
    energy /= AUDIO_FRAME_SAMPLES;

    if (energy < 100.0f) {
        printf("[FAIL] audio_decode output too quiet: energy=%.1f\n", energy);
        audio_destroy(&ctx);
        return -1;
    }

    audio_destroy(&ctx);
    return 0;
}
