// SPDX-License-Identifier: Apache-2.0 
// Copyright 2023 Authors of Tarian & the Organization created Tarian
//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

// Structure to hold the data that will be sent as an event.
struct event_data
{
    unsigned long args[3];// Array to store arguments captured by the kprobe.
};
const struct event_data *unused __attribute__((unused));

// Define the BPF map to hold the perf event array.
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

// Kprobe handler for the __x64_sys_accept function.
SEC("kprobe/__x64_sys_accept")
/**
 * kprobe_accept is the implementation of a kprobe attached to the __x64_sys_accept function.
 * The __x64_sys_accept function is used to accept a connection. This is a blocking call,
 * and if there is no connection available, it will block until one is available.
 *
 * @param ctx - Pointer to the structure containing registers set by the kernel.
 * @return Returns 0 on success and -1 on failure.
 */
int kprobe_accept(struct pt_regs *ctx)
{
    struct event_data args = {};// Create an event_data struct to capture the arguments.
    // Read the first argument of __x64_sys_accept and store it in args.
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&args.args[0], sizeof(args.args[0]), &PT_REGS_PARM1(ctx2));

     // Read the second argument of __x64_sys_accept and store it in args.
    bpf_probe_read(&args.args[1], sizeof(args.args[1]), &PT_REGS_PARM2(ctx2));

    // Emit the captured arguments as an event using the perf event array.
    bpf_perf_event_output(ctx, &event, BPF_F_CURRENT_CPU, &args, sizeof(args));

    // Return 0 to continue the execution of the probed function.
    return 0;
}
// License information for the eBPF program.
char _license[] SEC("license") = "Dual MIT/GPL";