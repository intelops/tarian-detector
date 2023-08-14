// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "headers.h"

// data gathered by this program
struct event_data {
  int id;
  event_context_t e_ctx;

  int fd;
  __u8 binary_filepath[MAX_STRING_SIZE];
  __u8 user_comm[MAX_LOOP][MAX_STRING_SIZE];
  __u8 env_vars[MAX_LOOP][MAX_STRING_SIZE];
  int flags;

  __s64 ret;
};

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(event);

// entry
SEC("kprobe/__x64_sys_execveat")
int kprobe_execveat_entry(struct pt_regs *ctx) {
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

  ed->fd = PT_REGS_PARM1_CORE(ctx2);

  // binary File path
  __s64 res = BPF_READ_STR((char *)PT_REGS_PARM2_CORE(ctx2), &ed->binary_filepath);
  if (res < 0) {
    BPF_RINGBUF_DISCARD(ed);
    return -1;
  }

  // user command
  read_str_arr_to_ptr((const char *const *)PT_REGS_PARM3_CORE(ctx2),
                      ed->user_comm);

  // environment variables
  read_str_arr_to_ptr((const char *const *)PT_REGS_PARM4_CORE(ctx2),
                      ed->env_vars);

  ed->flags = PT_REGS_PARM5_CORE(ctx);

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// exit
SEC("kretprobe/__x64_sys_execveat")
int kretprobe_execveat_exit(struct pt_regs *ctx) {
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
  ed->ret = PT_REGS_RC_CORE(ctx2);

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
