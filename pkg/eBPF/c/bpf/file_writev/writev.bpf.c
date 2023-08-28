// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "includes.h"

// data gathered by this program
struct event_data {
  event_context_t eventContext;

  int id;
  unsigned long fd;
  unsigned long vlen;
  long int ret;
};

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(writev_event_map);

// entry
SEC("kprobe/__x64_sys_writev")
int kprobe_writev_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an writev_event_map in map.
  ed = BPF_RINGBUF_RESERVE(writev_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 0;

  // sets the context
  init_context(&ed->eventContext);

  sys_args_t sys_args;
  read_sys_args_into(&sys_args, ctx);

  // file descriptor
  ed->fd = (unsigned long)sys_args[0];

  ed->vlen = (unsigned long)sys_args[2];

  // pushes the information to ringbuf writev_event_map mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// exit
SEC("kretprobe/__x64_sys_writev")
int kretprobe_writev_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an writev_event_map in map.
  ed = BPF_RINGBUF_RESERVE(writev_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  init_context(&ed->eventContext);

  //return value - long int
  ed->ret = (long int)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf writev_event_map mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
