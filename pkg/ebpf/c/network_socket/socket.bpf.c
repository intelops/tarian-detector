// SPDX-License-Identifier: Apache-2.0 
// Copyright 2023 Authors of Tarian & the Organization created Tarian
//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

// Define the structure for event data
struct event_data
{
    __u32 domain;
    __u32 type;
    int protocol;
    ;
};
const struct event_data *unused __attribute__((unused));

// Define the perf event array map with maximum 1 << 24 entries
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

// Define the kprobe for the __x64_sys_listen function
SEC("kprobe/__x64_sys_socket")
/**
*This is the implementation of kprobe to the __x64_sys_socket function 
* sys_socket ( pt_regs * ctx ) Returns information about the socket.
*/
int kprobe_socket(struct pt_regs *ctx)
{
    // Create a struct to store the event data
    struct event_data args = {};

    // Extract the first two arguments from the pt_regs of the kprobe event
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&args.domain, sizeof(args.domain), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args.type, sizeof(args.type), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args.protocol, sizeof(args.protocol), &PT_REGS_PARM3(ctx2));

    // Output the event data to the perf event array
    bpf_perf_event_output(ctx, &event, BPF_F_CURRENT_CPU, &args, sizeof(args));

    // Return 0 to continue the execution of the probed function.
    return 0;
}

// Define the license for the BPF program
char _license[] SEC("license") = "Dual MIT/GPL";