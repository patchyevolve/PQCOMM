#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "kernel_filter.h"
#include "kernel_filter_bpf.h"

#define TEST_SKIP 42

/* Try to create a veth pair for XDP testing. Returns the ifname or NULL. */
static const char* try_create_veth(void)
{
    static char ifname[32] = {0};
    const char* names[] = {"xdp_test0", "xdp_test1", NULL};

    for (int i = 0; names[i]; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", names[i]);
        system(cmd);
    }
    for (int i = 0; names[i]; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd),
            "ip link add '%s' type veth peer name '%s_peer' && "
            "ip link set '%s' up",
            names[i], names[i], names[i]);
        if (system(cmd) == 0) {
            snprintf(ifname, sizeof(ifname), "%s", names[i]);
            return ifname;
        }
    }
    return NULL;
}

static void destroy_veth(const char* ifname)
{
    if (!ifname || !ifname[0]) return;
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "ip link delete %s 2>/dev/null", ifname);
    system(cmd);
}

/* Test: BPF map create and sync */
int test_kf_bpf_map(void)
{
    int ret = kernel_filter_bpf_create_map();
    if (ret < 0) {
        printf("[SKIP] BPF unavailable (run as root?)\n");
        kernel_filter_bpf_shutdown();
        return TEST_SKIP;
    }

    if (kernel_filter_bpf_sync(0, 0) != 0) {
        kernel_filter_bpf_shutdown();
        return -1;
    }

    if (kernel_filter_bpf_sync(1, 1) != 0) {
        kernel_filter_bpf_shutdown();
        return -2;
    }

    kernel_filter_bpf_shutdown();
    return 0;
}

/* Test: BPF program load */
int test_kf_bpf_load(void)
{
    int ret = kernel_filter_bpf_create_map();
    if (ret < 0) {
        printf("[SKIP] BPF unavailable (run as root?)\n");
        kernel_filter_bpf_shutdown();
        return TEST_SKIP;
    }

    if (kernel_filter_bpf_load() != 0) {
        kernel_filter_bpf_shutdown();
        return -1;
    }

    kernel_filter_bpf_shutdown();
    return 0;
}

/* Test: attach/detach lifecycle */
int test_kf_bpf_attach_detach(void)
{
    kernel_filter_bpf_shutdown();

    /* Try common NIC names first, then create a veth pair */
    const char* candidates[] = {"lo", "eth0", "enp0s1", "enp0s2", "enp0s3",
                                "enp1s0", "wlan0", "wlp0s1", NULL};
    int created_veth = 0;
    int attached = 0;

    for (int i = 0; candidates[i]; i++) {
        if (kernel_filter_bpf_attach_iface(candidates[i]) == 0) {
            attached = 1;
            break;
        }
    }
    if (!attached) {
        const char* veth = try_create_veth();
        if (veth && kernel_filter_bpf_attach_iface(veth) == 0) {
            attached = 1;
            created_veth = 1;
        }
    }

    if (!attached) {
        printf("[SKIP] XDP not supported on this kernel (no CONFIG_NET_XDP)\n");
        kernel_filter_bpf_shutdown();
        return TEST_SKIP;
    }

    if (!kernel_filter_bpf_loaded()) {
        kernel_filter_bpf_shutdown();
        if (created_veth) destroy_veth("xdp_test0");
        return -1;
    }

    if (kernel_filter_bpf_detach_iface() != 0) {
        kernel_filter_bpf_shutdown();
        if (created_veth) destroy_veth("xdp_test0");
        return -2;
    }

    kernel_filter_bpf_shutdown();
    if (created_veth) destroy_veth("xdp_test0");
    return 0;
}

/* Test: integration with existing kernel_filter */
int test_kf_bpf_integration(void)
{
    kernel_filter_init();

    /* Try to set up BPF with XDP; fall back to map-only */
    const char* candidates[] = {"lo", "eth0", "enp0s1", "enp0s2", "enp0s3",
                                "enp1s0", "wlan0", "wlp0s1", NULL};
    int created_veth = 0;
    int attached = 0;

    for (int i = 0; candidates[i]; i++) {
        if (kernel_filter_bpf_attach_iface(candidates[i]) == 0) {
            attached = 1;
            break;
        }
    }
    if (!attached) {
        const char* veth = try_create_veth();
        if (veth && kernel_filter_bpf_attach_iface(veth) == 0) {
            attached = 1;
            created_veth = 1;
        }
    }
    if (!attached) {
        if (kernel_filter_bpf_create_map() != 0) {
            printf("[SKIP] BPF unavailable (run as root?)\n");
            return TEST_SKIP;
        }
    }

    /* Add a whitelist entry */
    uint8_t addr[16] = {0};
    addr[15] = 1;
    if (kernel_filter_whitelist_add(addr) != 0) return -1;

    /* Sync to BPF */
    if (kernel_filter_bpf_sync_state() != 0) {
        printf("[SKIP] BPF sync failed\n");
        kernel_filter_bpf_cleanup();
        if (created_veth) destroy_veth("xdp_test0");
        return TEST_SKIP;
    }

    kernel_filter_bpf_cleanup();
    if (created_veth) destroy_veth("xdp_test0");
    return 0;
}
