// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "includes.h"

// data gathered by this program
struct event_data {
  event_context_t eventContext;
  int id;

  int flags;
  int ret;
  short unsigned int mode;

  __u8 filename[4096];
};

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(event);

// entry
SEC("kprobe/__x64_sys_open")
int kprobe_open_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an event in map.
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 0;

  // sets the context
  init_context(&ed->eventContext);

  sys_args_t sys_args;
  read_sys_args_into(&sys_args, ctx);

  __s64 res = BPF_READ_STR((char *)sys_args[0], &ed->filename);
  if (res < 0) {
    BPF_RINGBUF_DISCARD(ed);
    return -1;
  }

  ed->flags = (int)sys_args[1];

  ed->mode = (short unsigned int)sys_args[2];

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// exit
SEC("kretprobe/__x64_sys_open")
int kretprobe_open_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an event in map.
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  init_context(&ed->eventContext);

  // return value - int
  ed->ret = (int)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
