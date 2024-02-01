// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

// go:build ignore

#include "common.h"

// stain bool Continue() {
//   struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//   int ppid = BPF_CORE_READ(task, parent, pid);
//   if (ppid != 489466)
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

  /*====================== PARAMETERS ======================*/
  tdf_flex_save(&te, TDT_STR, get_syscall_param(regs, 0) /* filename */, 0,USER);
  tdf_flex_save(&te, TDT_STR_ARR, get_syscall_param(regs, 1) /* argv */, 0,USER);
  tdf_flex_save(&te, TDT_STR_ARR, get_syscall_param(regs, 2) /* envp */, 0,USER);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_execve")
int BPF_KRETPROBE(tdf_execve_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVE_R, &te, FIXED, TDS_EXECVE_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S32, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_execveat")
int BPF_KPROBE(tdf_execveat_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVEAT_E, &te, VARIABLE, TDS_EXECVEAT_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd /* fd */);

  tdf_flex_save(&te, TDT_STR, get_syscall_param(regs, 1) /* filename */, 0, USER);
  tdf_flex_save(&te, TDT_STR_ARR, get_syscall_param(regs, 2) /* argv */, 0, USER);
  tdf_flex_save(&te, TDT_STR_ARR, get_syscall_param(regs, 3) /* envp */, 0, USER);

  int flags = get_syscall_param(regs, 4);
  tdf_save(&te, TDT_S32, &flags /* flags */);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_execveat")
int BPF_KRETPROBE(tdf_execveat_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVEAT_R, &te, FIXED, TDS_EXECVEAT_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S32, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_clone")
int BPF_KPROBE(tdf_clone_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_CLONE_E, &te, FIXED, TDS_CLONE_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  uint64_t flags = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_U64, &flags /* clone_flags */);

  uint64_t newsp = get_syscall_param(regs, 1);
  tdf_save(&te, TDT_U64, &newsp /* newsp */);

  int parent_tid;
  bpf_probe_read_user_str(&parent_tid, sizeof(parent_tid), (void *)get_syscall_param(regs, 2));
  tdf_save(&te, TDT_S32, &parent_tid /* parent_tidptr */);

  int child_tid;
  bpf_probe_read_user_str(&child_tid, sizeof(child_tid), (void *)get_syscall_param(regs, 3));
  tdf_save(&te, TDT_S32, &child_tid /* child_tidptr */);

  uint64_t tls = get_syscall_param(regs, 4);
  tdf_save(&te, TDT_U64, &tls /* tls */);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_clone")
int BPF_KRETPROBE(tdf_clone_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_CLONE_R, &te, FIXED, TDS_CLONE_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S32, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_close")
int BPF_KPROBE(tdf_close_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_CLOSE_E, &te, FIXED, TDS_CLOSE_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd /* fd */);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_close")
int BPF_KRETPROBE(tdf_close_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_CLOSE_R, &te, FIXED, TDS_CLOSE_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S32, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_read")
int BPF_KPROBE(tdf_read_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_READ_E, &te, VARIABLE, TDS_READ_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int32_t fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd /* fd */);

  uint32_t count = get_syscall_param(regs, 2);
  bpf_printk("Execve %d", count);

  tdf_flex_save(&te, TDT_BYTE_ARR, get_syscall_param(regs, 1), count, USER);

  tdf_save(&te, TDT_U32, &count /* count */);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_read")
int BPF_KRETPROBE(tdf_read_r, long ret) { 
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_READ_R, &te, FIXED, TDS_READ_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S64, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_write")
int BPF_KPROBE(tdf_write_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_WRITE_E, &te, VARIABLE, TDS_WRITE_E);
  if (resp != TDC_SUCCESS) return resp;
 
  /*====================== PARAMETERS ======================*/
  int32_t fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd /* fd */);

  uint32_t count = get_syscall_param(regs, 2);
  bpf_printk("Execve %d", count);

  tdf_flex_save(&te, TDT_BYTE_ARR, get_syscall_param(regs, 1), count, USER);

  tdf_save(&te, TDT_U32, &count /* count */);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}


KRETPROBE("__x64_sys_write")
int BPF_KRETPROBE(tdf_write_r, long ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_WRITE_R, &te, FIXED, TDS_WRITE_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S64, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_open")
int BPF_KPROBE(tdf_open_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_OPEN_E, &te, VARIABLE, TDS_OPEN_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_flex_save(&te, TDT_STR, get_syscall_param(regs, 0), 0, USER);

  int flags = get_syscall_param(regs, 1);
  tdf_save(&te, TDT_S32, &flags);

  unsigned int mode = get_syscall_param(regs, 2);
  tdf_save(&te, TDT_U32, &mode);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_open")
int BPF_KRETPROBE(tdf_open_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_OPEN_R, &te, FIXED, TDS_OPEN_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_U32, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_readv")
int BPF_KPROBE(tdf_readv_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_READV_E, &te, VARIABLE, TDS_READV_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd);

  int vlen = get_syscall_param(regs, 2);

  tdf_flex_save(&te, TDT_IOVEC_ARR, get_syscall_param(regs, 1), vlen, USER);

  tdf_save(&te, TDT_S32, &vlen);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_readv")
int BPF_KRETPROBE(tdf_readv_r,  long ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_READV_R, &te, FIXED, TDS_READV_R);
  if (resp != TDC_SUCCESS) return resp;
  
  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S64, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}


KPROBE("__x64_sys_writev")
int BPF_KPROBE(tdf_writev_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_WRITEV_E, &te, VARIABLE, TDS_WRITEV_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd);

  int vlen = get_syscall_param(regs, 2);
  tdf_flex_save(&te, TDT_IOVEC_ARR, get_syscall_param(regs, 1), vlen, USER);

  tdf_save(&te, TDT_S32, &vlen);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_writev")
int BPF_KRETPROBE(tdf_writev_r,  long ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_WRITEV_R, &te, FIXED, TDS_WRITEV_R);
  if (resp != TDC_SUCCESS) return resp;
  
  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S64, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_openat")
int BPF_KPROBE(tdf_openat_e, struct pt_regs  *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_OPENAT_E, &te, VARIABLE, TDS_OPENAT_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int dfd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32,  &dfd);

  tdf_flex_save(&te, TDT_STR, get_syscall_param(regs, 1), 0, USER);

  int flags = get_syscall_param(regs , 2);
  tdf_save(&te, TDT_S32, &flags);

  unsigned int  mode = get_syscall_param(regs, 3);
  tdf_save(&te, TDT_U32, &mode);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_openat")
int BPF_KRETPROBE(tdf_openat_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_OPENAT_R, &te, FIXED, TDS_OPENAT_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S32,  &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_openat2")
int BPF_KPROBE(tdf_openat2_e, struct pt_regs  *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_OPENAT2_E, &te, VARIABLE, TDS_OPENAT2_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int dfd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32,  &dfd);

  tdf_flex_save(&te, TDT_STR, get_syscall_param(regs, 1), 0, USER);

  struct open_how how = {0};
  bpf_probe_read_user((void *)&how, bpf_core_type_size(struct open_how), (void *)get_syscall_param(regs, 2));

  tdf_save(&te, TDT_S64, &how.flags);
  tdf_save(&te, TDT_S64, &how.mode);
  tdf_save(&te, TDT_S64, &how.resolve);

  int usize = get_syscall_param(regs, 3);
  tdf_save(&te, TDT_S32, &usize);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_openat2")
int BPF_KRETPROBE(tdf_openat2_r, long ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_OPENAT2_R, &te, FIXED, TDS_OPENAT2_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S64,  &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_listen")
int BPF_KPROBE(tdf_listen_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_LISTEN_E, &te, FIXED, TDS_LISTEN_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd);
  
  int backlog = get_syscall_param(regs, 1);
  tdf_save(&te, TDT_S32, &backlog);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
};

KRETPROBE("__x64_sys_listen")
int BPF_KRETPROBE(tdf_listen_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_LISTEN_R, &te, FIXED, TDS_LISTEN_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S32,  &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_socket")
int BPF_KPROBE(tdf_socket_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_SOCKET_E, &te, FIXED, TDS_SOCKET_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int family = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &family);
  
  int type = get_syscall_param(regs, 1);
  tdf_save(&te, TDT_S32, &type);

  int protocol = get_syscall_param(regs, 2);
  tdf_save(&te, TDT_S32, &protocol);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
};

KRETPROBE("__x64_sys_socket")
int BPF_KRETPROBE(tdf_socket_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_SOCKET_R, &te, FIXED, TDS_SOCKET_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S32,  &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_accept")
int BPF_KPROBE(tdf_accept_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_ACCEPT_E, &te, FIXED,  TDS_ACCEPT_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd);

  int addrlen;
  bpf_probe_read_user(&addrlen, sizeof(addrlen),  (void*)get_syscall_param(regs, 2));
  tdf_save(&te, TDT_S32, &addrlen);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_accept")
int BPF_KRETPROBE(tdf_accept_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_ACCEPT_R, &te, FIXED,  TDS_ACCEPT_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S32, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_bind")
int BPF_KPROBE(tdf_bind_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_BIND_E, &te, VARIABLE,  TDS_BIND_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd);

  int addrlen = get_syscall_param(regs, 2);
  tdf_flex_save(&te, TDT_SOCKADDR, get_syscall_param(regs, 1), addrlen, USER);

  tdf_save(&te, TDT_S32, &addrlen);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_bind")
int BPF_KRETPROBE(tdf_bind_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_BIND_R, &te, FIXED,  TDS_BIND_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S32, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_connect")
int BPF_KPROBE(tdf_connect_e, struct pt_regs *regs) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_CONNECT_E, &te, VARIABLE,  TDS_CONNECT_E);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  int fd = get_syscall_param(regs, 0);
  tdf_save(&te, TDT_S32, &fd);

  int addrlen = get_syscall_param(regs, 2);
  tdf_flex_save(&te, TDT_SOCKADDR, get_syscall_param(regs, 1), addrlen, USER);

  tdf_save(&te, TDT_S32, &addrlen);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}

KRETPROBE("__x64_sys_connect")
int BPF_KRETPROBE(tdf_connect_r, int ret) {
  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_CONNECT_R, &te, FIXED,  TDS_CONNECT_R);
  if (resp != TDC_SUCCESS) return resp;

  /*====================== PARAMETERS ======================*/
  tdf_save(&te, TDT_S32, &ret);
  /*====================== PARAMETERS ======================*/

  return tdf_submit_event(&te);
}