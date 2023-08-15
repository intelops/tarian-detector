// SPDX-License-Identifier: Apache-2.0 
// Copyright 2023 Authors of Tarian & the Organization created Tarian
//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define AF_INET 2
#define AF_INET6 10
#define AF_UNIX 1
#define MAX_UNIX_PATH 108  // standard size for UNIX paths

// Structure to hold the data that will be sent as an event.
struct event_data
{
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    int fd;
    __u16 sa_family;
    __u16 port;  
    struct {
        __be32 s_addr;
    } v4_addr;
    struct {
    __u8 s6_addr[16];
    } v6_addr;
    struct {
        char path[MAX_UNIX_PATH];
    } unix_addr;
    __u32 padding2;

};
const struct event_data *unused __attribute__((unused));

// Define the ringbuff map with maximum 1 << 24 entries
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

static inline __u16 my_ntohs(__u16 port) {
  return (port >> 8) | (port << 8);
}

// Kprobe handler for the __x64_sys_accept function.
SEC("kprobe/__x64_sys_accept")
/**
 * kprobe_accept is the implementation of a kprobe attached to the __x64_sys_accept function.
 * The __x64_sys_accept function is used to accept a connection. This is a blocking call,
 * and if there is no connection available, it will block until one is available.
 */
int kprobe_accept(struct pt_regs *ctx)
{
    struct event_data *ed; // Pointer to hold the reserved space in the ring buffer
    ed = bpf_ringbuf_reserve(&event, sizeof(struct event_data), 0); // Reserve space in ring buffer for event data
    if (!ed) {
    return 0;
    }
        //Process Id and Thread Group Id
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ed->pid = pid_tgid >> 32;
    ed->tgid = pid_tgid;

        //User Id and Group Id
    __u64 uid_gid = bpf_get_current_uid_gid();
    ed->uid = uid_gid >> 32;
    ed->gid = uid_gid;

    // Extract the first two arguments from the pt_regs of the kprobe event
   struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx); // Extract the first parameter
    ed->fd=(int)PT_REGS_PARM1_CORE(ctx2);
   struct sockaddr *uservaddr_ptr=(struct sockaddr *)PT_REGS_PARM2_CORE(ctx2);

    // Determine the socket type by inspecting the sockaddr.sa_family field
    bpf_probe_read_user(&ed->sa_family, sizeof(ed->sa_family), uservaddr_ptr);
    bpf_printk("sa_family: %u\n", ed->sa_family);

    // Handle data based on the socket type
    switch (ed->sa_family) {
        case AF_INET:
        {
            struct sockaddr_in v4;
            bpf_probe_read_user(&v4, sizeof(v4), uservaddr_ptr);
            ed->v4_addr.s_addr = v4.sin_addr.s_addr;
            ed->port = my_ntohs(v4.sin_port); // Convert from network to host byte order
            bpf_printk("IPv4 Address: %u, Port: %u\n", ed->v4_addr.s_addr, ed->port);
        }
            break;
        case AF_INET6:
        {
        struct sockaddr_in6 v6;
        bpf_probe_read_user(&v6, sizeof(v6), uservaddr_ptr);
        // Copying the IPv6 address
        #pragma unroll
        for (int i = 0; i < 16; i++) {
            ed->v6_addr.s6_addr[i] = v6.sin6_addr.in6_u.u6_addr8[i];
        }
        // Reading the IPv6 port
        ed->port = my_ntohs(v6.sin6_port); // Convert from network to host byte order
        bpf_printk("IPv6 Address: %u, Port: %u\n", ed->v6_addr.s6_addr, ed->port);
        }
            break;
        case AF_UNIX:
            bpf_probe_read_user(&ed->unix_addr, sizeof(struct sockaddr_un), uservaddr_ptr);
            break;
    }
    bpf_ringbuf_submit(ed, 0); // Submit the event to the ring buffer for userspace to consume
    return 0;
}
// License information for the eBPF program.
char _license[] SEC("license") = "Dual MIT/GPL";