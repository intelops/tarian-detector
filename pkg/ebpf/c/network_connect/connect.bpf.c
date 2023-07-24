// SPDX-License-Identifier: Apache-2.0 
// Copyright 2023 Authors of Tarian & the Organization created Tarian
//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

struct event_data{
    unsigned long args[3];
};
const struct event_data *unused __attribute__((unused));

struct{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

SEC("kprobe/__x64_sys_connect")
/**
*This is the implementation of kprobe to __x64_sys_connect function.
* This function is called when the system is about to connect. The purpose of this function is to establish a connection to the system on behalf of the caller.
* @param ctx - * Pointer to the thread context.
* @return Returns 0 on success or - 1 on failure. 
*/
int kprobe_connect(struct pt_regs * ctx){
    struct event_data args = {};
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&args.args[0], sizeof(args.args[0]), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args.args[1], sizeof(args.args[1]), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args.args[2], sizeof(args.args[2]), &PT_REGS_PARM3(ctx2));
    bpf_perf_event_output(ctx, &event, BPF_F_CURRENT_CPU, &args, sizeof(args));
return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";