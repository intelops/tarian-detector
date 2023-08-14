#ifndef __COMMON_CONTEXT_H__
#define __COMMON_CONTEXT_H__

#include "common.h"
#include "types.h"
#include "task.h"

static __always_inline int set_context(event_context_t *e_ctx) {

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // system boot time
  e_ctx->ts = bpf_ktime_get_ns();

  // thread start time 
  e_ctx->start_time = get_task_start_time(task);

  // process Id and thread Group Id
  get_pid_tgid(&e_ctx->pid, &e_ctx->tgid);

  // real_parent process id
  e_ctx->ppid = get_task_ppid(task);
  
  // group leader process id
  e_ctx->glpid = get_task_glpid(task);

  // user Id and group Id
  get_uid_gid(&e_ctx->uid, &e_ctx->gid);

  // nodename
  BPF_READ_STR(get_task_node_name(task), &e_ctx->nodename);

  // Command trigred event
  BPF_GET_COMM(e_ctx->comm);

  // current working directory
  __s64 res = get_cwd(&e_ctx->cwd);
  if (res < 0) {
    return -1;
  }

  return 0;
}

#endif