#pragma once
#include <stdint.h>

#define VIDEO_MAX_FRAME_SIZE 256 * 1024  /* 256KB max per frame */
#define VIDEO_WIDTH 640
#define VIDEO_HEIGHT 480
#define VIDEO_FPS 15
#define VIDEO_QUALITY 70

typedef struct {
    void* pipe;
    int active;
    char device[64];
    int width;
    int height;
    int fps;
} video_capture_t;

typedef struct {
    void* pipe;
    int active;
    char device[64];
    int width;
    int height;
} video_display_t;

int video_capture_init(video_capture_t* cap, const char* device, int vid_w, int vid_h, int fps);
void video_capture_close(video_capture_t* cap);
int video_capture_read_jpeg(video_capture_t* cap, uint8_t* buf, uint32_t* len, uint32_t max_len);

int video_display_init(video_display_t* disp, const char* device, int w, int h);
void video_display_close(video_display_t* disp);
int video_display_show_jpeg(video_display_t* disp, const uint8_t* jpeg, uint32_t len,
                            const char* save_dir, int frame_num);
