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
    unsigned long args[3];
};
const struct event_data *unused __attribute__((unused));

// Define the perf event array map with maximum 1 << 24 entries
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

// Define the kprobe for the __x64_sys_bind function
SEC("kprobe/__x64_sys_bind")
/**
* This is the implementation of kprobe to the x64_sys_bind function. This function is called when the system binds to a process.
* @param ctx - * Pointer to the context. 
* @return Returns 0 on success non - zero on failure. 
*/
int kprobe_bind(struct pt_regs *ctx)
{
    struct event_data args = {};
        
    // Extract the third argument from the pt_regs of the kprobe event
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);

    // Read the first argument of __x64_sys_bind and store it in args.
    bpf_probe_read(&args.args[0], sizeof(args.args[0]), &PT_REGS_PARM1(ctx2));
    
    // Read the second argument of __x64_sys_bind and store it in args.
    bpf_probe_read(&args.args[1], sizeof(args.args[1]), &PT_REGS_PARM2(ctx2));

    // Output the event data to the perf event array
    bpf_perf_event_output(ctx, &event, BPF_F_CURRENT_CPU, &args, sizeof(args));

    // Return 0 on success
    return 0;
}

// Define the license for the eBPF program
char _license[] SEC("license") = "Dual MIT/GPL";