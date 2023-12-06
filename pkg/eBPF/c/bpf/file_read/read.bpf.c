// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "includes.h"

// data gathered by this program
struct event_data {
  int id;
  event_context_t eventContext;

  int fd;
  long unsigned int count;
  long int ret;
};

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(read_event_map);

// entry
SEC("kprobe/__x64_sys_read")
int kprobe_read_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an read_event_map in map.
  ed = BPF_RINGBUF_RESERVE(read_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 0;

  // sets the context
  init_context(&ed->eventContext);

  sys_args_t sys_args;
  read_sys_args_into(&sys_args, ctx);

  // file descriptor
  ed->fd = (unsigned int)sys_args[0];

  // count
  ed->count = (long unsigned int)sys_args[2];

  // pushes the information to ringbuf read_event_map mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// exit
SEC("kretprobe/__x64_sys_read")
int kretprobe_read_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an read_event_map in map.
  ed = BPF_RINGBUF_RESERVE(read_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  init_context(&ed->eventContext);

  // return value - long int
  ed->ret = (long int)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf read_event_map mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
