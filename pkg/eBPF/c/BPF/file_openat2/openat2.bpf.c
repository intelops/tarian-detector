// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "headers.h"

// data gathered by this program
struct event_data {
  event_context_t eventContext;

  int id;
  int fd;
  long usize;
  long ret;

  struct open_how how;
  __u8 filename[4096];
};

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(event);

// entry
SEC("kprobe/__x64_sys_openat2")
int kprobe_openat2_entry(struct pt_regs *ctx) {
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
  ed->fd = (int)PT_REGS_PARM1_CORE(ctx2);

  // filename
  long res = BPF_READ_STR((char *)PT_REGS_PARM2_CORE(ctx2), &ed->filename);
  if (res < 0) {
    BPF_RINGBUF_DISCARD(ed);
    return -1;
  }
  
  // open how struct
  res = BPF_READ_STR((struct open_how *)PT_REGS_PARM3_CORE(ctx2), &ed->how);
  if(res < 0) {
    BPF_RINGBUF_DISCARD(ed);
    return -1;
  }

  // usize
  ed->usize = (long unsigned int)PT_REGS_PARM4_CORE(ctx2);

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// exit
SEC("kretprobe/__x64_sys_openat2")
int kretprobe_openat2_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an event in map.
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  set_context(&ed->eventContext);

  // return value - long
  ed->ret = (long)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
