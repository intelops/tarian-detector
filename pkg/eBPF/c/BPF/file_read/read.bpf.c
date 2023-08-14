// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "headers.h"

// data gathered by this program
struct event_data {
  int id;
  event_context_t e_ctx;

  __u32 fd;
  //   __u8 buf[4096];
  __u64 count;

  __u64 ret;
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
  set_context(&ed->e_ctx);

  struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
  ed->fd = (unsigned int)PT_REGS_PARM1_CORE(ctx2);

  //   __s64 res =
  //       BPF_READ_STR((char *)PT_REGS_PARM2_CORE(ctx2), &ed->buf);
  //   if (res < 0) {
  //     BPF_RINGBUF_DISCARD(ed);
  //     return -1;
  //   }

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
  set_context(&ed->e_ctx);

  struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
  ed->ret = (unsigned long)PT_REGS_RC_CORE(ctx2);

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};