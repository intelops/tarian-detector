// SPDX-License-Identifier: Apache-2.0 
// Copyright 2023 Authors of Tarian & the Organization created Tarian
//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

struct event_data
{
    __u32 domain;
    __u32 type;
    int protocol;
    ;
};
const struct event_data *unused __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

SEC("kprobe/__x64_sys_socket")
/**
*This is the implementation of kretprobe to the __x64_sys_socket function 
* sys_socket ( pt_regs * ctx ) Returns information about the socket.
* @param ctx - * context from the trace call. A pointer to the struct pt_regs which contains the return value.
* @return 0 if successful non - zero 
*/
int kprobe_socket(struct pt_regs *ctx)
{
    struct event_data args = {};
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&args.domain, sizeof(args.domain), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args.type, sizeof(args.type), &PT_REGS_PARM2(ctx2));
    bpf_probe_read(&args.protocol, sizeof(args.protocol), &PT_REGS_PARM3(ctx2));
    bpf_perf_event_output(ctx, &event, BPF_F_CURRENT_CPU, &args, sizeof(args));
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";