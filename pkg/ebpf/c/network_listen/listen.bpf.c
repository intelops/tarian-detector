// SPDX-License-Identifier: Apache-2.0 
// Copyright 2023 Authors of Tarian & the Organization created Tarian
//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

struct event_data
{
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    int fd;
    int backlog; 
};
const struct event_data *unused __attribute__((unused));
// Define the ringbuff map with maximum 1 << 24 entries

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

SEC("kprobe/__x64_sys_listen")
/**
 * kprobe_listen is a kprobe attached to the function __x64_sys_listen.
 * It captures the arguments of the function call and emits them as an event.
 */
int kprobe_listen(struct pt_regs *ctx)
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
    ed->backlog=(int)PT_REGS_PARM2_CORE(ctx2);
    bpf_ringbuf_submit(ed, 0); // Submit the event to the ring buffer for userspace to consume
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";