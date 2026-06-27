#include "audio_pipeline.h"
#include <string.h>
#include <stdio.h>

int test_jitter_basic(void)
{
    jitter_buffer_t jb;
    jitter_init(&jb, 40);

    if (jb.target_frames != 2) {
        printf("[FAIL] expected target_frames=2, got %u\n", jb.target_frames);
        return -1;
    }

    audio_frame_t f;
    memset(&f, 0, sizeof(f));
    f.seq = 1;

    if (jitter_push(&jb, &f) != 0) {
        printf("[FAIL] jitter_push failed\n");
        return -1;
    }
    if (jb.count != 1) {
        printf("[FAIL] expected count=1\n");
        return -1;
    }

    /* should not pop yet (need target_frames=2) */
    audio_frame_t out;
    if (jitter_pop(&jb, &out) != -1) {
        printf("[FAIL] expected pop fail (not enough frames)\n");
        return -1;
    }

    memset(&f, 0, sizeof(f));
    f.seq = 2;
    jitter_push(&jb, &f);

    if (jitter_pop(&jb, &out) != 0) {
        printf("[FAIL] jitter_pop should succeed now\n");
        return -1;
    }

    if (out.seq != 1) {
        printf("[FAIL] expected seq=1, got %lu\n", (unsigned long)out.seq);
        return -1;
    }

    printf("[PASS] test_jitter_basic\n");
    return 0;
}
