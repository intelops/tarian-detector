// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "headers.h"

// data gathered by this program.
struct event_data {
  __u32 pid;
  __u32 tgid;
  __u32 uid;
  __u32 gid;

  __u8 comm[16];
  __u8 cwd[32];
  __u8 binary_filepath[MAX_STRING_SIZE];
  __u8 user_comm[MAX_LOOP][MAX_STRING_SIZE];
  __u8 env_vars[MAX_LOOP][MAX_STRING_SIZE];
};

// Force emits struct event_data into the elf.
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(event);

// program attaches to sys_execve syscall
SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an event in map.
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    return 0;
  }

  s64 res;

  // process Id and thread Group Id
  get_pid_tgid(&ed->pid, &ed->tgid);

  // user Id and group Id
  get_uid_gid(&ed->uid, &ed->gid);

  // Command trigred event
  BPF_GET_COMM(ed->comm);

  // binary File path
  struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);

  res = BPF_READ_STR((char *)PT_REGS_PARM1_CORE(ctx2), &ed->binary_filepath);
  if (res < 0) {
    BPF_RINGBUF_DISCARD(ed);
    return 1;
  }

  // current working directory
  res = get_cwd(&ed->cwd);
  if (res < 0) {
    BPF_RINGBUF_DISCARD(ed);
    return 1;
  }

  // user command
  read_str_arr_to_ptr((const char *const *)PT_REGS_PARM2_CORE(ctx2),
                      ed->user_comm);

  // environment variables
  read_str_arr_to_ptr((const char *const *)PT_REGS_PARM3_CORE(ctx2),
                      ed->env_vars);

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
}
