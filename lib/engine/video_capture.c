#include "video_capture.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <io.h>
#include <direct.h>
#define popen _popen
#define pclose _pclose
#define mkdir _mkdir
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

int video_capture_init(video_capture_t* cap, const char* device, int vid_w, int vid_h, int fps)
{
    if (!cap) return -1;
    memset(cap, 0, sizeof(*cap));

    cap->width = vid_w > 0 ? vid_w : VIDEO_WIDTH;
    cap->height = vid_h > 0 ? vid_h : VIDEO_HEIGHT;
    cap->fps = fps > 0 ? fps : VIDEO_FPS;

    char cmd[512];
#ifdef _WIN32
    (void)device;
    snprintf(cmd, sizeof(cmd),
             "ffmpeg -hide_banner -loglevel error "
             "-f dshow -framerate %d -video_size %dx%d -i video=\"%s\" "
             "-f image2pipe -vcodec mjpeg -qscale:v %d - 2>NUL",
             cap->fps, cap->width, cap->height,
             device ? device : "Integrated Webcam",
             VIDEO_QUALITY);
    cap->pipe = popen(cmd, "rb");
#else
    char dev[64];
    if (device && device[0])
        snprintf(dev, sizeof(dev), "%s", device);
    else
        snprintf(dev, sizeof(dev), "/dev/video0");

    snprintf(cmd, sizeof(cmd),
             "ffmpeg -hide_banner -loglevel error "
             "-f v4l2 -framerate %d -video_size %dx%d -i %s "
             "-f image2pipe -vcodec mjpeg -qscale:v %d - 2>/dev/null",
             cap->fps, cap->width, cap->height, dev, VIDEO_QUALITY);
    cap->pipe = popen(cmd, "r");
#endif
    if (!cap->pipe) return -1;
    cap->active = 1;
    if (device) snprintf(cap->device, sizeof(cap->device), "%s", device);
    return 0;
}

void video_capture_close(video_capture_t* cap)
{
    if (!cap || !cap->active) return;
    if (cap->pipe) pclose((FILE*)cap->pipe);
    cap->active = 0;
    cap->pipe = NULL;
}

int video_capture_read_jpeg(video_capture_t* cap, uint8_t* buf, uint32_t* len, uint32_t max_len)
{
    if (!cap || !cap->active || !cap->pipe || !buf || !len) return -1;

    uint32_t pos = 0;
    while (pos < max_len) {
        size_t r = fread(buf + pos, 1, 1, (FILE*)cap->pipe);
        if (r != 1) return -1;
        pos++;
        if (pos >= 2 && buf[pos-2] == 0xFF && buf[pos-1] == 0xD9) {
            *len = pos;
            return 0;
        }
    }
    return -1;
}

int video_display_init(video_display_t* disp, const char* device, int w, int h)
{
    if (!disp) return -1;
    memset(disp, 0, sizeof(*disp));
    (void)device;
    disp->width = w > 0 ? w : VIDEO_WIDTH;
    disp->height = h > 0 ? h : VIDEO_HEIGHT;
    disp->active = 1;
#ifdef _WIN32
    mkdir("C:\\Temp\\ssm_video");
#else
    mkdir("/tmp/ssm_video", 0700);
#endif
    return 0;
}

void video_display_close(video_display_t* disp)
{
    if (!disp) return;
    disp->active = 0;
}

int video_display_show_jpeg(video_display_t* disp, const uint8_t* jpeg, uint32_t len,
                            const char* save_dir, int frame_num)
{
    if (!disp || !disp->active || !jpeg || !len) return -1;

    char path[512];
#ifdef _WIN32
    const char* dir = save_dir ? save_dir : "C:\\Temp\\ssm_video";
    mkdir(dir);
    snprintf(path, sizeof(path), "%s\\frame_%05d.jpg", dir, frame_num);
#else
    const char* dir = save_dir ? save_dir : "/tmp/ssm_video";
    mkdir(dir, 0700);
    snprintf(path, sizeof(path), "%s/frame_%05d.jpg", dir, frame_num);
#endif

    FILE* f = fopen(path, "wb");
    if (!f) return -1;
    fwrite(jpeg, 1, len, f);
    fclose(f);
    return 0;
}
