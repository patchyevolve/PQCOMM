#include "kernel_filter_bpf.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
/* Windows stub — BPF is Linux-only */
int kernel_filter_bpf_create_map(void) { return -1; }
void kernel_filter_bpf_destroy_map(void) {}
int kernel_filter_bpf_sync(uint32_t whitelist_enabled, uint32_t blocklist_enabled)
    { (void)whitelist_enabled; (void)blocklist_enabled; return -1; }
int kernel_filter_bpf_load(void) { return -1; }
int kernel_filter_bpf_attach(const char* ifname) { (void)ifname; return -1; }
int kernel_filter_bpf_detach(void) { return -1; }
int kernel_filter_bpf_is_attached(void) { return 0; }
void kernel_filter_bpf_shutdown(void) {}
#else
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <errno.h>

#define BPF_LOG_BUF_SIZE 65536

/* BPF instruction helpers (from kernel samples/bpf/bpf_insn.h) */
#define BPF_ALU64_IMM(OP, DST, IMM)             \
    ((struct bpf_insn) {                        \
        .code = BPF_ALU64 | BPF_OP(OP) | BPF_K, \
        .dst_reg = DST,                         \
        .src_reg = 0,                           \
        .off = 0,                               \
        .imm = IMM })

#define BPF_MOV64_IMM(DST, IMM) BPF_ALU64_IMM(BPF_MOV, DST, IMM)
#define BPF_EXIT_INSN()                         \
    ((struct bpf_insn) {                        \
        .code = BPF_JMP | BPF_EXIT,             \
        .dst_reg = 0,                           \
        .src_reg = 0,                           \
        .off = 0,                               \
        .imm = 0 })

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)         \
    ((struct bpf_insn) {                        \
        .code = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM, \
        .dst_reg = DST,                         \
        .src_reg = 0,                           \
        .off = OFF,                             \
        .imm = IMM })

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)        \
    ((struct bpf_insn) {                        \
        .code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, \
        .dst_reg = DST,                         \
        .src_reg = SRC,                         \
        .off = OFF,                             \
        .imm = 0 })

#define BPF_JMP_IMM(OP, DST, IMM, OFF)          \
    ((struct bpf_insn) {                        \
        .code = BPF_JMP | BPF_OP(OP) | BPF_K,  \
        .dst_reg = DST,                         \
        .src_reg = 0,                           \
        .off = OFF,                             \
        .imm = IMM })

#define BPF_JMP_REG(OP, DST, SRC, OFF)          \
    ((struct bpf_insn) {                        \
        .code = BPF_JMP | BPF_OP(OP) | BPF_X,  \
        .dst_reg = DST,                         \
        .src_reg = SRC,                         \
        .off = OFF,                             \
        .imm = 0 })

#define BPF_LD_ABS(SIZE, IMM)                   \
    ((struct bpf_insn) {                        \
        .code = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS, \
        .dst_reg = 0,                           \
        .src_reg = 0,                           \
        .off = 0,                               \
        .imm = IMM })

/* BPF syscall wrappers */
static int bpf(enum bpf_cmd cmd, union bpf_attr* attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

/* Simple XDP program that drops packets on a given port */
static struct bpf_insn xdp_drop_on_port[] = {
    /* Load ethertype from offset 12 */
    BPF_LD_ABS(BPF_H, 12),
    /* If not 0x0800 (IPv4), pass */
    BPF_JMP_IMM(BPF_JNE, 0, 0x0800, 6),
    /* Load IPv4 protocol from offset 23 (after ethernet header) */
    BPF_LD_ABS(BPF_B, 23),
    /* If not UDP (17), pass */
    BPF_JMP_IMM(BPF_JNE, 0, 17, 4),
    /* Load UDP dest port from offset 36 (ether 14 + ip 20 + udp 2) */
    BPF_LD_ABS(BPF_H, 36),
    /* Compare with our target port (stored in map value) */
    BPF_JMP_IMM(BPF_JNE, 0, 9001, 2),
    /* Drop */
    BPF_MOV64_IMM(0, 1),
    BPF_EXIT_INSN(),
    /* Pass */
    BPF_MOV64_IMM(0, 2),
    BPF_EXIT_INSN(),
};

static int g_bpf_map_fd = -1;
static int g_bpf_prog_fd = -1;
static int g_bpf_attached = 0;
static char g_bpf_ifname[64];

int kernel_filter_bpf_create_map(void)
{
    if (g_bpf_map_fd >= 0) return -1;

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 1;

    g_bpf_map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    return g_bpf_map_fd;
}

void kernel_filter_bpf_destroy_map(void)
{
    if (g_bpf_map_fd >= 0) {
        close(g_bpf_map_fd);
        g_bpf_map_fd = -1;
    }
}

int kernel_filter_bpf_sync(uint32_t key, uint32_t value)
{
    if (g_bpf_map_fd < 0) return -1;

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = g_bpf_map_fd;
    attr.key = (uint64_t)(uintptr_t)&key;
    attr.value = (uint64_t)(uintptr_t)&value;
    attr.flags = 0;

    return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

int kernel_filter_bpf_load(void)
{
    if (g_bpf_prog_fd >= 0) return -1;

    /* Load the XDP program */
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_XDP;
    attr.insns = (uint64_t)(uintptr_t)xdp_drop_on_port;
    attr.insn_cnt = sizeof(xdp_drop_on_port) / sizeof(xdp_drop_on_port[0]);
    attr.license = (uint64_t)(uintptr_t)"GPL";
    attr.log_buf = 0;
    attr.log_size = 0;
    attr.log_level = 0;

    g_bpf_prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    if (g_bpf_prog_fd < 0) return -1;

    return 0;
}

int kernel_filter_bpf_unload(void)
{
    if (g_bpf_prog_fd >= 0) {
        close(g_bpf_prog_fd);
        g_bpf_prog_fd = -1;
    }
    return 0;
}

int kernel_filter_bpf_attach(const char* ifname)
{
    if (g_bpf_attached) return -1;
    if (g_bpf_prog_fd < 0) return -1;

    int ifindex = if_nametoindex(ifname);
    if (ifindex <= 0) return -1;

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.target_ifindex = ifindex;
    attr.attach_bpf_fd = g_bpf_prog_fd;
    attr.attach_type = BPF_XDP;
    attr.attach_flags = 0;

    if (bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) != 0) {
        return -1;
    }

    g_bpf_attached = 1;
    snprintf(g_bpf_ifname, sizeof(g_bpf_ifname), "%s", ifname);
    return 0;
}

int kernel_filter_bpf_detach(void)
{
    if (!g_bpf_attached) return -1;
    if (!g_bpf_ifname[0]) return -1;

    int ifindex = if_nametoindex(g_bpf_ifname);
    if (ifindex <= 0) return -1;

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.target_ifindex = ifindex;
    attr.attach_type = BPF_XDP;
    attr.attach_flags = 0;

    bpf(BPF_PROG_DETACH, &attr, sizeof(attr));
    g_bpf_attached = 0;
    g_bpf_ifname[0] = '\0';
    return 0;
}

int kernel_filter_bpf_is_attached(void)
{
    return g_bpf_attached;
}

void kernel_filter_bpf_shutdown(void)
{
    kernel_filter_bpf_destroy_map();
    kernel_filter_bpf_unload();
    g_bpf_attached = 0;
    g_bpf_ifname[0] = '\0';
}
#endif /* _WIN32 */
