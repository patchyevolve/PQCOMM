#pragma once
/* Platform abstraction header for cross-platform support
 *
 * Provides unified types, sleep, threads, sockets, file ops,
 * and timing across POSIX and Windows.
 */

#ifdef _WIN32
#define _WIN32_WINNT 0x0601  /* Windows 7+ */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <io.h>
#include <direct.h>
#else
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#endif

/* Platform-independent thread type */
#ifdef _WIN32
typedef HANDLE platform_thread_t;
typedef DWORD (WINAPI *platform_thread_fn_t)(LPVOID);
#else
typedef pthread_t platform_thread_t;
typedef void* (*platform_thread_fn_t)(void*);
#endif

/* Sleep (milliseconds) */
static inline void platform_sleep_ms(uint32_t ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

/* Clock monotonic milliseconds */
static inline uint64_t platform_now_ms(void)
{
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
#endif
}

/* Create a thread */
static inline int platform_thread_create(platform_thread_t* thr,
                                          platform_thread_fn_t fn, void* arg)
{
#ifdef _WIN32
    *thr = CreateThread(NULL, 0, fn, arg, 0, NULL);
    return *thr ? 0 : -1;
#else
    return pthread_create(thr, NULL, fn, arg);
#endif
}

/* Join a thread */
static inline int platform_thread_join(platform_thread_t thr)
{
#ifdef _WIN32
    return WaitForSingleObject(thr, INFINITE) == WAIT_OBJECT_0 ? 0 : -1;
#else
    return pthread_join(thr, NULL);
#endif
}

/* Detach a thread */
static inline int platform_thread_detach(platform_thread_t thr)
{
#ifdef _WIN32
    CloseHandle(thr);
    return 0;
#else
    return pthread_detach(thr);
#endif
}

/* Platform-independent file operations */
static inline int platform_mkdir(const char* path)
{
#ifdef _WIN32
    return _mkdir(path);
#else
    return mkdir(path, 0700);
#endif
}

static inline int platform_chmod(const char* path, int mode)
{
#ifdef _WIN32
    (void)path;
    (void)mode;
    return 0; /* Windows doesn't have chmod for regular files */
#else
    return chmod(path, (mode_t)mode);
#endif
}

static inline int platform_stat_exists(const char* path)
{
#ifdef _WIN32
    return _access(path, 0) == 0;
#else
    struct stat st;
    return stat(path, &st) == 0;
#endif
}

/* Secure memory locking (best-effort on each platform) */
static inline int platform_mlock(void* addr, size_t len)
{
#ifdef __linux__
    return mlock(addr, len);
#elif defined(_WIN32)
    return VirtualLock(addr, len) ? 0 : -1;
#else
    (void)addr; (void)len;
    return 0;
#endif
}

static inline int platform_munlock(void* addr, size_t len)
{
#ifdef __linux__
    return munlock(addr, len);
#elif defined(_WIN32)
    return VirtualUnlock(addr, len) ? 0 : -1;
#else
    (void)addr; (void)len;
    return 0;
#endif
}

/* Inet_pton replacement for Windows */
static inline int platform_inet_pton(int af, const char* src, void* dst)
{
#ifdef _WIN32
    return InetPtonA(af, src, dst);
#else
    return inet_pton(af, src, dst);
#endif
}

/* Inet_ntop replacement */
static inline const char* platform_inet_ntop(int af, const void* src,
                                              char* dst, int size)
{
#ifdef _WIN32
    return InetNtopA(af, (void*)src, dst, (int)size);
#else
    return inet_ntop(af, src, dst, (socklen_t)size);
#endif
}
