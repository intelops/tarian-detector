// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

// This directive ensures that the Go tooling will ignore this file.
// go:build ignore

// Includes required header files.
#include "includes.h"

// Data structure to capture event details related to socket operations.
struct event_data {
  event_context_t eventContext; // General context related to the event.

  int id;       // Identifier for the event type (entry/exit).
  __u32 domain; // Domain of the socket (e.g., AF_INET, AF_INET6).
  __u32 type;   // Type of the socket (e.g., SOCK_STREAM, SOCK_DGRAM).
  __u32
      protocol; // Protocol used by the socket (e.g., IPPROTO_TCP, IPPROTO_UDP).
  int ret;      // Return value (used for exit events).
};

// Dummy variable to ensure event_data struct is present in the generated ELF
// file.
const struct event_data *unused __attribute__((unused));

// Definition for the ring buffer map to store the events.
BPF_RINGBUF_MAP(event);

// Kprobe handler for the __x64_sys_socket function entry.
SEC("kprobe/__x64_sys_socket")
int kprobe_socket_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // Allocate space in the ring buffer map for a new event.
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    // Allocation failed.
    return -1;
  }

  // Set event ID for entry.
  ed->id = 0;

  // Initialize the event context.
  init_context(&ed->eventContext);

  sys_args_t sys_args;
  // Read system call arguments into sys_args.
  read_sys_args_into(&sys_args, ctx);

  // Extract and store the domain, type, and protocol arguments from sys_args.
  ed->domain = (int)sys_args[0];
  ed->type = (int)sys_args[1];
  ed->protocol = (int)sys_args[2];

  // Submit the captured data to the ring buffer.
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
}

// Kretprobe handler for the __x64_sys_openat function exit.
// Note: The function name "kretprobe_socket_exit" suggests that it should be
// related to socket, but the SEC macro suggests it's for "openat". Please
// ensure this is intended.
SEC("kretprobe/__x64_sys_openat")
int kretprobe_socket_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // Allocate space in the ring buffer map for a new event.
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    // Allocation failed.
    return -1;
  }

  // Set event ID for exit.
  ed->id = 1;

  // Initialize the event context.
  init_context(&ed->eventContext);

  // Capture and store the return value from the system call.
  ed->ret = (int)PT_REGS_RC_CORE(ctx);

  // Submit the captured data to the ring buffer.
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
}
