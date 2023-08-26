// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "includes.h"

// Struct representing the event data captured by this program
struct event_data {
  event_context_t eventContext; // Context for the event

  int id;      // Identifier for the event type (entry or exit)
  int fd;      // File descriptor associated with the event
  int backlog; // Queue length for completely established sockets waiting to be
               // accepted
  int ret;     // Return value, used for capturing syscall exit values
};

// Attribute forces inclusion of event_data struct in the ELF binary output,
// even if it seems unused
const struct event_data *unused __attribute__((unused));

// Defines a ringbuffer map named 'event'
BPF_RINGBUF_MAP(event);

// eBPF program attached to the entry of the '__x64_sys_listen' kernel function
SEC("kprobe/__x64_sys_listen")
int kprobe_listen_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // Reserve space for an event in the ringbuffer map
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    return -1; // Return if space allocation failed
  }

  ed->id = 0; // Set event type to 'entry'

  // Initialize event context
  init_context(&ed->eventContext);

  sys_args_t sys_args;
  // Populate sys_args with syscall arguments from the context
  read_sys_args_into(&sys_args, ctx);

  // Extract and store the file descriptor from syscall arguments
  ed->fd = (int)sys_args[0];

  // Extract and store the backlog value from syscall arguments
  ed->backlog = (int)sys_args[1];

  // Submit the captured event data to the ringbuffer map
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// eBPF program attached to the exit of the '__x64_sys_listen' kernel function
SEC("kretprobe/__x64_sys_listen")
int kretprobe_listen_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // Reserve space for an event in the ringbuffer map
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    return -1; // Return if space allocation failed
  }

  ed->id = 1; // Set event type to 'exit'

  // Initialize event context
  init_context(&ed->eventContext);

  // Capture the return value of the syscall
  ed->ret = (int)PT_REGS_RC_CORE(ctx);

  // Submit the captured event data to the ringbuffer map
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};