// SPDX-License-Identifier: Apache-2.0 
// Copyright 2023 Authors of Tarian & the Organization created Tarian
//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

// Define the structure for event data
struct event_data{
    unsigned long args[3];
};
const struct event_data *unused __attribute__((unused));

// Define the ringbuff map with maximum 1 << 24 entries
struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

// Define the kprobe for the __x64_sys_connect function
SEC("kprobe/__x64_sys_connect")
/**
*This is the implementation of kprobe to __x64_sys_connect function.
* This function is called when the system is about to connect. 
*/
int kprobe_connect(struct pt_regs * ctx){
    struct event_data args = {};
    // Create a struct to store the event data
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    
    // Extract the first three arguments from the pt_regs of the kprobe event
    bpf_probe_read(&args.args[0], sizeof(args.args[0]), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args.args[1], sizeof(args.args[1]), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args.args[2], sizeof(args.args[2]), &PT_REGS_PARM3(ctx2));

    // Output the event data to the perf event array
    struct event_data *task_info; // Pointer to hold the reserved space in the ring buffer
    task_info = bpf_ringbuf_reserve(&event, sizeof(struct event_data), 0); // Reserve space in ring buffer for event data
    if (!task_info) {
    return 0;
    }
    *task_info = args; // Copy the extracted args into the reserved space
    bpf_ringbuf_submit(task_info, 0); // Submit the event to the ring buffer for userspace to consume
    return 0;
}

// Define the license for the BPF program
char _license[] SEC("license") = "Dual MIT/GPL";