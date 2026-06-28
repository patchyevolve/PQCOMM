#pragma once
#include <stdint.h>

/* eBPF/XDP integration for kernel_filter.
 * Provides hardware-offload-like packet filtering at the XDP layer.
 * Falls back to software filter when BPF is unavailable.
 */

/* Create BPF map (whitelist/blocklist flags) */
int kernel_filter_bpf_create_map(void);

/* Load the BPF XDP filter program */
int kernel_filter_bpf_load(void);

/* Attach XDP program to interface (e.g. "eth0").
 * Returns 0 on success, -1 if BPF not available or attach fails. */
int kernel_filter_bpf_attach(const char* ifname);

/* Detach XDP program from interface */
int kernel_filter_bpf_detach(void);

/* Sync whitelist/blocklist state to BPF map */
int kernel_filter_bpf_sync(uint32_t whitelist_enabled, uint32_t blocklist_enabled);

/* Check if XDP is currently attached */
int kernel_filter_bpf_is_attached(void);

/* Clean up all BPF resources */
void kernel_filter_bpf_shutdown(void);
