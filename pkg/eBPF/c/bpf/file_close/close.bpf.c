// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "common.h"

// data gathered by this program
struct event_data {
  event_context_t eventContext;
  int id;

  int fd;
  int ret;
};

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(close_event_map);

// entry
SEC("kprobe/__x64_sys_close")
int kprobe_close_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an close_event_map in map.
  ed = BPF_RINGBUF_RESERVE(close_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 0;

  // sets the context
  init_context(&ed->eventContext);

  sys_args_t sys_args;
  read_sys_args_into(&sys_args, ctx);

  // file descriptor - int
  ed->fd = (int)sys_args[0];

  // pushes the information to ringbuf close_event_map map
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// exit
SEC("kretprobe/__x64_sys_close")
int kretprobe_close_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an close_event_map in map.
  ed = BPF_RINGBUF_RESERVE(close_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  init_context(&ed->eventContext);

  // return value - int
  ed->ret = (int)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf close_event_map map
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
