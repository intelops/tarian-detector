// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "headers.h"

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
BPF_RINGBUF_MAP(event);

// entry
SEC("kprobe/__x64_sys_read")
int kprobe_read_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an event in map.
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 0;

  // sets the context
  set_context(&ed->eventContext);

  struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);

  // file descriptor
  ed->fd = (unsigned int)PT_REGS_PARM1_CORE(ctx2);

  // count
  ed->count = (long unsigned int)PT_REGS_PARM3_CORE(ctx2);

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// exit
SEC("kretprobe/__x64_sys_read")
int kretprobe_read_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an event in map.
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  set_context(&ed->eventContext);

  // return value - long int
  ed->ret = (long int)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
