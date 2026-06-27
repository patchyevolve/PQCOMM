#include "audio_capture.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int audio_capture_init(audio_capture_t* cap, const char* device)
{
    if (!cap) return -1;
    memset(cap, 0, sizeof(*cap));

    char cmd[256];
    if (device && device[0])
        snprintf(cmd, sizeof(cmd),
                 "arecord -q -r %d -c %d -f %s -t raw -D %s 2>/dev/null",
                 AUDIO_PCM_SAMPLE_RATE, AUDIO_PCM_CHANNELS,
                 AUDIO_PCM_FORMAT, device);
    else
        snprintf(cmd, sizeof(cmd),
                 "arecord -q -r %d -c %d -f %s -t raw 2>/dev/null",
                 AUDIO_PCM_SAMPLE_RATE, AUDIO_PCM_CHANNELS,
                 AUDIO_PCM_FORMAT);

    cap->pipe = popen(cmd, "r");
    if (!cap->pipe) return -1;
    cap->active = 1;
    if (device) snprintf(cap->device, sizeof(cap->device), "%s", device);
    return 0;
}

void audio_capture_close(audio_capture_t* cap)
{
    if (!cap || !cap->active) return;
    if (cap->pipe) pclose((FILE*)cap->pipe);
    cap->active = 0;
    cap->pipe = NULL;
}

int audio_capture_read(audio_capture_t* cap, int16_t* samples, uint32_t frame_samples)
{
    if (!cap || !cap->active || !cap->pipe || !samples) return -1;

    size_t needed = (size_t)frame_samples * sizeof(int16_t);
    size_t got = fread(samples, 1, needed, (FILE*)cap->pipe);
    if (got < needed) return -1;
    return 0;
}

int audio_playback_init(audio_playback_t* play, const char* device)
{
    if (!play) return -1;
    memset(play, 0, sizeof(*play));

    char cmd[256];
    if (device && device[0])
        snprintf(cmd, sizeof(cmd),
                 "aplay -q -r %d -c %d -f %s -t raw -D %s 2>/dev/null",
                 AUDIO_PCM_SAMPLE_RATE, AUDIO_PCM_CHANNELS,
                 AUDIO_PCM_FORMAT, device);
    else
        snprintf(cmd, sizeof(cmd),
                 "aplay -q -r %d -c %d -f %s -t raw 2>/dev/null",
                 AUDIO_PCM_SAMPLE_RATE, AUDIO_PCM_CHANNELS,
                 AUDIO_PCM_FORMAT);

    play->pipe = popen(cmd, "w");
    if (!play->pipe) return -1;
    play->active = 1;
    if (device) snprintf(play->device, sizeof(play->device), "%s", device);
    return 0;
}

void audio_playback_close(audio_playback_t* play)
{
    if (!play || !play->active) return;
    if (play->pipe) pclose((FILE*)play->pipe);
    play->active = 0;
    play->pipe = NULL;
}

int audio_playback_write(audio_playback_t* play, const int16_t* samples, uint32_t frame_samples)
{
    if (!play || !play->active || !play->pipe || !samples) return -1;

    size_t needed = (size_t)frame_samples * sizeof(int16_t);
    size_t wrote = fwrite(samples, 1, needed, (FILE*)play->pipe);
    if (wrote < needed) return -1;
    fflush((FILE*)play->pipe);
    return 0;
}
