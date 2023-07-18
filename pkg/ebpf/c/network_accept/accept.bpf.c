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

SEC("kprobe/__x64_sys_accept")
int kprobe_accept(struct pt_regs * ctx){
        struct event_data args = {};
    
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx);
    bpf_probe_read(&args.args[0], sizeof(args.args[0]), &PT_REGS_PARM1(ctx2));
    bpf_probe_read(&args.args[1], sizeof(args.args[1]), &PT_REGS_PARM2(ctx2));
  

    u32 tgid = bpf_get_current_pid_tgid();
    bpf_printk("Accept Socket Fd : %d\n",args.args[0]);
    bpf_printk("Accept Socket raw Address: %d\n", args.args[1]);
   


bpf_perf_event_output(ctx, &event, BPF_F_CURRENT_CPU, &args, sizeof(args));
return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";