// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

#define MAX_SIZE 256

// data gathered by this program.
struct event_data {
  __u32 pid;
  __u32 tgid;
  __u32 uid;
  __u32 gid;
  __s32 syscall_nr;
  __s64 ret;

  __u8 comm[16];
  __u8 cwd[32];
};

// Force emits struct event_data into the elf.
const struct event_data *unused __attribute__((unused));

// sys_exit_execve data structure
// can be found at below path
//  /sys/kernel/debug/tracing/events/syscalls/sys_exit_execve/format
struct execve_exit_struct {
  __u16 common_type;
  __u8 common_flags;
  __u8 common_preempt_count;
  __s32 common_pid;

  __s32 syscall_nr;
  __s64 ret;
};

// ringbuffer map definition
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} event SEC(".maps");

// null bytes
static char zero[MAX_SIZE] SEC(".rodata") = {0};

// program attaches to sys_exit_execve syscall
SEC("tracepoint/syscalls/sys_exit_execve")
int execve_exit(struct execve_exit_struct *ctx) {
  struct event_data *ed;

  // allocate space for an event in map.
  ed = bpf_ringbuf_reserve(&event, sizeof(struct event_data), 0);
  if (!ed) {
    return 0;
  }

  s64 res;

  // syscall number
  ed->syscall_nr = ctx->syscall_nr;

  // return value
  ed->ret = ctx->ret;

  // process Id and thread Group Id
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  ed->pid = pid_tgid >> 32;
  ed->tgid = pid_tgid;

  // user Id and group Id
  __u64 uid_gid = bpf_get_current_uid_gid();
  ed->uid = uid_gid >> 32;
  ed->gid = uid_gid;

  // command triggred event
  bpf_get_current_comm(&ed->comm, sizeof(ed->comm));

  // current working directory
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct fs_struct *fs;
  struct dentry *dentry;

  bpf_probe_read_kernel(&fs, sizeof(fs), &task->fs);
  bpf_probe_read_kernel(&dentry, sizeof(dentry), &fs->pwd.dentry);
  res = bpf_probe_read_kernel_str(&ed->cwd, sizeof(ed->cwd), &dentry->d_iname);
  if (res < 0) {
    bpf_ringbuf_discard(ed, 0);
    return 1;
  }

  // pushes the information to ringbuf event mamp
  bpf_ringbuf_submit(ed, 0);

  return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
