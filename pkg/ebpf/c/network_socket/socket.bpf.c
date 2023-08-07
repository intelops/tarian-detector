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
    // Create a struct to store the event data
    struct event_data args = {};

    // Extract the first two arguments from the pt_regs of the kprobe event
    struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1(ctx); // Extract the first parameter
    bpf_probe_read(&args.domain, sizeof(args.domain), &PT_REGS_PARM1(ctx2)); // Read the domain argument
    bpf_probe_read(&args.type, sizeof(args.type), &PT_REGS_PARM2(ctx2)); // Read the type argument
    bpf_probe_read(&args.protocol, sizeof(args.protocol), &PT_REGS_PARM3(ctx2)); // Read the protocol argument

    // Output the event data to the perf event array
    struct event_data *task_info; // Pointer to hold the reserved space in the ring buffer
    task_info = bpf_ringbuf_reserve(&event, sizeof(struct event_data), 0); // Reserve space in ring buffer for event data
    if (!task_info) {
    return 0;
    }
    *task_info = args; // Copy the extracted args into the reserved space
    bpf_ringbuf_submit(task_info, 0); // Submit the event to the ring buffer for userspace to consume
    return 0;
}

// Define the license for the BPF program
char _license[] SEC("license") = "Dual MIT/GPL";