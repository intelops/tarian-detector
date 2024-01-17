// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

// go:build ignore

#include "common.h"

stain bool Continue() {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  int ppid = BPF_CORE_READ(task, parent, pid);
  if (ppid != 525465)
    return false;

  return true;
}
const tarian_meta_data_t *unused __attribute__((unused));

#define MAX_LOOP 16
KPROBE("__x64_sys_execve")
int BPF_KPROBE(tdf_execve_e, struct pt_regs *regs) {
  if (!Continue())
    return TDC_FAILURE;

  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVE_E, &te, TDS_EXECVE_E);
  if (resp != TDC_SUCCESS)
    return resp;

  resp = tdf_flex_save(&te, TDT_STR, PT_REGS_PARM1_CORE(regs), MAX_STRING_SIZE, USER);
  if (resp != TDC_SUCCESS)
    return resp;

  resp = tdf_flex_save(&te, TDT_STR_ARR, PT_REGS_PARM3_CORE(regs),
                       MAX_STRING_SIZE, USER);
  if (resp != TDC_SUCCESS)
    return resp;

//   resp = tdf_flex_save(&te, TDT_STR_ARR, PT_REGS_PARM2_CORE(regs),
//                        MAX_STRING_SIZE, USER);
//   if (resp != TDC_SUCCESS)
//     return resp;

  print_event(&te);
  bpf_printk("Execve e %ld --%s--", te.buf.pos, "here");

  return tdf_submit_event(&te);
}
