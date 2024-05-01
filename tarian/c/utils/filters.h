// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

#ifndef __UTILS_FILTERS_H__
#define __UTILS_FILTERS_H__

#include "index.h"

stain bool can_proceed();
stain bool has_same_ppid(uint32_t);
stain bool has_same_comm(char *, int);
stain bool is_self_generated();

stain bool can_proceed() {
  // skip self generated event. self generated events are the events which are
  // generated due to the actions of this tool itself. (e.g, /proc/<pid>/cgroup
  // file open for kubernetes enrichment at userspace side)
  if (is_self_generated())
    return false;

  return true;
}

// has_same_pid checks if the event has same pid as the current task.
stain bool has_same_pid(uint32_t pid) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  uint32_t c_pid = get_task_ns_tgid(task);

  return (c_pid == pid);
}

stain bool has_same__host_pid(uint32_t pid) {
  u64 fpid = bpf_get_current_pid_tgid() >> 32;

  return (fpid == pid);
}

stain bool has_same_ppid(uint32_t ppid) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  uint32_t c_ppid = BPF_CORE_READ(task, parent, pid);

  return (c_ppid == ppid);
}

stain bool has_same_comm(char *comm, int len) {
  char buf[TASK_COMM_LEN];
  bpf_get_current_comm(&buf, TASK_COMM_LEN);

  for (int i = 0; i < TASK_COMM_LEN; i++) {
    if (i == len)
      break;

    if (buf[i] != comm[i])
      return false;
  }

  return true;
}

stain bool is_self_generated() {
  uint32_t pid = get__tarian_app_pid();
  if (pid == -1)
    return false; // dont want to lose events due to errors

  return has_same_pid(pid);
}
#endif
