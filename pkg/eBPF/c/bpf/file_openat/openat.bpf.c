// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "includes.h"

// data gathered by this program
struct event_data {
  event_context_t eventContext;

  short unsigned int mode;
  int id;
  int fd;
  int flags;
  int ret;

  __u8 filename[4096];
};

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(openat_event_map);

// entry
SEC("kprobe/__x64_sys_openat")
int kprobe_openat_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an openat_event_map in map.
  ed = BPF_RINGBUF_RESERVE(openat_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 0;

  // sets the context
  init_context(&ed->eventContext);

  sys_args_t sys_args;
  read_sys_args_into(&sys_args, ctx);

  // file descriptor
  ed->fd = (int)sys_args[0];

  // filename
  __s64 res = BPF_READ_STR((char *)sys_args[1], &ed->filename);
  if (res < 0) {
    BPF_RINGBUF_DISCARD(ed);
    return -1;
  }

  // flags
  ed->flags = (int)sys_args[2];

  // mode
  ed->mode = (short unsigned int)sys_args[3];

  // pushes the information to ringbuf openat_event_map mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// exit
SEC("kretprobe/__x64_sys_openat")
int kretprobe_openat_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an openat_event_map in map.
  ed = BPF_RINGBUF_RESERVE(openat_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  init_context(&ed->eventContext);

  // return value - int
  ed->ret = (int)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf openat_event_map mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
