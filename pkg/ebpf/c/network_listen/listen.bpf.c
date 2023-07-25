// SPDX-License-Identifier: Apache-2.0 
// Copyright 2023 Authors of Tarian & the Organization created Tarian
//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

struct event_data
{
    unsigned long args[3];
};
const struct event_data *unused __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

SEC("kprobe/__x64_sys_listen")
/**
 * kprobe_listen is a kprobe attached to the function __x64_sys_listen.
 * It captures the arguments of the function call and emits them as an event.
 */
int kprobe_listen(struct pt_regs *ctx)
{
    struct event_data args = {};
    
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
   
    // Read the first argument of __x64_sys_listen and store it in args.
    bpf_probe_read(&args.args[0], sizeof(args.args[0]), &PT_REGS_PARM1(ctx2));

    // Read the second argument of __x64_sys_listen and store it in args.
    bpf_probe_read(&args.args[1], sizeof(args.args[1]), &PT_REGS_PARM2(ctx2));

    // Emit the captured arguments as an event.
    bpf_perf_event_output(ctx, &event, BPF_F_CURRENT_CPU, &args, sizeof(args));
    
    // Return 0 to continue the execution of the probed function.
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";