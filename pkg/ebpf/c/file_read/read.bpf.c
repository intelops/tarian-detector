// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

// data gathered by this program.
struct event_data{
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;

    __u8 buf[256];
    __u32 fd;
};

const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

// program attaches to sys_read syscall
SEC("kprobe/__x64_sys_read")
int kprobe_read(struct pt_regs * ctx){
    
    struct event_data *ed;
    
    // allocate space for an event in map.
    ed = bpf_ringbuf_reserve(&event, sizeof(struct event_data), 0);
    if (!ed){
        return 0;
    }
    
    // process Id and thread Group Id
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    ed->pid = pid_tgid >> 32;
    ed->tgid = pid_tgid;

    // user Id and group Id
    __u64 uid_gid = bpf_get_current_uid_gid();
    ed->uid = uid_gid >> 32;
    ed->gid = uid_gid;

    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);

    // file descriptor
    ed->fd = (int)PT_REGS_PARM1_CORE(ctx2);
    
    // filepath
    char *buf = (char *)PT_REGS_PARM2_CORE(ctx2);
    bpf_probe_read_user_str(&ed->buf, sizeof(ed->buf), buf);

    bpf_ringbuf_submit(ed, 0);
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";