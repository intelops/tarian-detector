// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "common.h"

// data gathered by this program.
struct event_data {
  int id;
  event_context_t eventContext;

  int ret;

  __u8 binary_filepath[MAX_STRING_SIZE];
  __u8 user_comm[MAX_LOOP][MAX_STRING_SIZE];
  __u8 env_vars[MAX_LOOP][MAX_STRING_SIZE];
};

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(execve_event_map);

//entry
SEC("kprobe/__x64_sys_execve")
int kprobe_execve_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an execve_event_map in map.
  ed = BPF_RINGBUF_RESERVE(execve_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 0;

  // sets the context
  init_context(&ed->eventContext);

  sys_args_t sys_args;
  read_sys_args_into(&sys_args, ctx);
  
  // binary File path
  __s64 res = BPF_READ_STR((char *)sys_args[0], &ed->binary_filepath);
  if (res < 0) {
    BPF_RINGBUF_DISCARD(ed);
    return -1;
  }

  // user command
  read_str_arr_to_ptr((const char *const *)sys_args[1],
                      ed->user_comm);

  // environment variables
  read_str_arr_to_ptr((const char *const *)sys_args[2],
                      ed->env_vars);

  // pushes the information to ringbuf execve_event_map mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
}

// exit
SEC("kretprobe/__x64_sys_execve")
int kretprobe_execve_exit(struct pt_regs *ctx) {
  struct event_data *ed;
  
  // allocate space for an execve_event_map in map.
  ed = BPF_RINGBUF_RESERVE(execve_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  init_context(&ed->eventContext);

  ed->ret = (int)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf execve_event_map mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
}