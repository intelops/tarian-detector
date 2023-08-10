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
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u32 domain;     // Holds the domain of the socket (e.g., AF_INET, AF_INET6)
    __u32 type;       // Holds the type of the socket (e.g., SOCK_STREAM, SOCK_DGRAM)
    int protocol;     // Holds the protocol used by the socket (e.g., IPPROTO_TCP, IPPROTO_UDP)
};
const struct event_data *unused __attribute__((unused));

// Define the ringbuff event  map with maximum 1 << 24 entries
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF); // Specifies the type of BPF map as RINGBUF
    __uint(max_entries, 1 << 24); // Specifies the max number of entries in the ring buffer
} event SEC(".maps"); // Store this map in the ".maps" section

// Define the kprobe for the __x64_sys_listen function
SEC("kprobe/__x64_sys_socket")  // Attach this BPF program to the `__x64_sys_socket` kernel function
/**
*This is the implementation of kprobe to the __x64_sys_socket function 
* sys_socket ( pt_regs * ctx ) Returns information about the socket.
*/
int kprobe_socket(struct pt_regs *ctx) // Function definition for the kprobe
{

    struct event_data *ed; // Pointer to hold the reserved space in the ring buffer
    ed = bpf_ringbuf_reserve(&event, sizeof(struct event_data), 0); // Reserve space in ring buffer for event data
    if (!ed) {
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


    // Extract the first two arguments from the pt_regs of the kprobe event
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx); // Extract the first parameter

    ed->domain=(int)PT_REGS_PARM1_CORE(ctx2);// Read the domain argument
    ed->type =(int)PT_REGS_PARM2_CORE(ctx2); // Read the type argument
    ed->protocol=(int)PT_REGS_PARM3_CORE(ctx2);// Read the protocol argument

    bpf_ringbuf_submit(task_info, 0); // Submit the event to the ring buffer for userspace to consume
    return 0;
}

// Define the license for the BPF program
char _license[] SEC("license") = "Dual MIT/GPL";