// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

// go:build ignore

#include "common.h"

stain bool Continue() {
  // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  // int ppid = BPF_CORE_READ(task, parent, pid);
  // if (ppid != 449929)
  //   return false;

  return true;
}

const tarian_meta_data_t *unused __attribute__((unused));
const enum tarian_param_type_e *unsed_enum __attribute__((unused));
const enum tarian_events_e *Unused_enum_event __attribute__((unused));

#define MAX_LOOP 16
KPROBE("__x64_sys_execve")
int BPF_KPROBE(tdf_execve_e, struct pt_regs *regs) {
  if (!Continue())
    return TDC_FAILURE;

  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVE_E, &te, VARIABLE, TDS_EXECVE_E);
  if (resp != TDC_SUCCESS)
    return resp;

  // print_event(&te);
  tdf_flex_save(&te, TDT_STR, get_syscall_param(regs, 0), MAX_STRING_SIZE, USER);
  tdf_flex_save(&te, TDT_STR_ARR, get_syscall_param(regs, 1), MAX_STRING_SIZE, USER);
  tdf_flex_save(&te, TDT_STR_ARR, get_syscall_param(regs, 2), MAX_STRING_SIZE, USER);

  // print_event(&te);

  // bpf_override_return(ctx, -88);
  
  // // return
  // struct path path = BPF_CORE_READ(te.task, fs, pwd);
  // u16 slen = get_d_path_len(&path);

  // bpf_printk("Execve slenssssssssss %d", slen);

  tdf_submit_event(&te);

  return TDC_SUCCESS;
}

KRETPROBE("__x64_sys_execve")
int BPF_KRETPROBE(tdf_execve_r, int ret) {
  if (!Continue())
    return TDC_FAILURE;

  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVE_R, &te, FIXED, TDS_EXECVE_R);
  if (resp != TDC_SUCCESS)
    return resp;

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