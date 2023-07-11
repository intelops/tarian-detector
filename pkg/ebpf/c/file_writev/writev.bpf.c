//go:build ignore

#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"



struct event_data{
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;

    __u32 fd;
};

const struct event_data *unused __attribute__((unused));

struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event SEC(".maps");

SEC("kprobe/__x64_sys_writev")
int kprobe_writev(struct pt_regs * ctx){
    struct event_data *ed;
    ed = bpf_ringbuf_reserve(&event, sizeof(struct event_data), 0);
    if (!ed){
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

    //Filepath
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);

    ed->fd = (int)PT_REGS_PARM1_CORE(ctx2);

    bpf_ringbuf_submit(ed, 0);
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";