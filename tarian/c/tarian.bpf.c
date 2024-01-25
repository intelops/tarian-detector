// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

// go:build ignore

#include "common.h"

// stain bool Continue() {
//   struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//   int ppid = BPF_CORE_READ(task, parent, pid);
//   if (ppid != 707575)
//     return false;

//   return true;
// }

const tarian_meta_data_t *unused __attribute__((unused));
const enum tarian_param_type_e *unsed_enum __attribute__((unused));
const enum tarian_events_e *Unused_enum_event __attribute__((unused));

KPROBE("__x64_sys_execve")
int BPF_KPROBE(tdf_execve_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVE_E, &te, VARIABLE, TDS_EXECVE_E);
  if (resp != TDC_SUCCESS) return resp;

  tdf_flex_save(&te, TDT_STR, get_syscall_param(regs, 0), USER);
  tdf_flex_save(&te, TDT_STR_ARR, get_syscall_param(regs, 1), USER);
  tdf_flex_save(&te, TDT_STR_ARR, get_syscall_param(regs, 2), USER);

  return tdf_submit_event(&te);;
}

KRETPROBE("__x64_sys_execve")
int BPF_KRETPROBE(tdf_execve_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVE_R, &te, FIXED, TDS_EXECVE_R);
  if (resp != TDC_SUCCESS) return resp;

  tdf_save(&te, TDT_S32, &ret);

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_execveat")
int BPF_KPROBE(tdf_execveat_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVEAT_E, &te, VARIABLE, TDS_EXECVEAT_E);
  if (resp != TDC_SUCCESS) return resp;

  int fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd);
  
  tdf_flex_save(&te, TDT_STR, get_syscall_param(regs, 1), USER);
  tdf_flex_save(&te, TDT_STR_ARR, get_syscall_param(regs, 2), USER);
  tdf_flex_save(&te, TDT_STR_ARR, get_syscall_param(regs, 3), USER);

  int flags = get_syscall_param(regs, 4);
  tdf_save(&te, TDT_S32, &flags);

  return tdf_submit_event(&te);
}


KRETPROBE("__x64_sys_execveat")
int BPF_KRETPROBE(tdf_execveat_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVEAT_R, &te, FIXED, TDS_EXECVEAT_R);
  if (resp != TDC_SUCCESS) return resp;

  tdf_save(&te, TDT_S32, &ret);

  return tdf_submit_event(&te);
}

// KPROBE("__x64_sys_close")
// int BPF_KPROBE(tdf_close_e, struct pt_regs *regs) {
//   if (!Continue())
//     return TDC_FAILURE;

//   tarian_event_t te;
//   int resp = new_event(ctx, TDE_SYSCALL_CLOSE_E, &te, FIXED, TDS_CLOSE_E);
//   if (resp != TDC_SUCCESS) return resp;
  
//   int fd = get_syscall_param(regs, 0);
//   tdf_save(&te, TDT_S32, &fd);

//   return tdf_submit_event(&te);
// }
