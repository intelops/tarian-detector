#ifndef __COMMON_CONTEXT_H__
#define __COMMON_CONTEXT_H__

#include "common.h"
#include "types.h"
#include "task.h"

static __always_inline int set_context(event_context_t *eventContext) {

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // system boot time
  eventContext->ts = bpf_ktime_get_ns();

  // thread start time 
  eventContext->start_time = get_task_start_time(task);

  // process Id and thread Group Id
  get_pid_tgid(&eventContext->pid, &eventContext->tgid);

  // real_parent process id
  eventContext->ppid = get_task_ppid(task);
  
  // group leader process id
  eventContext->glpid = get_task_glpid(task);

  // user Id and group Id
  get_uid_gid(&eventContext->uid, &eventContext->gid);

  // nodename
  // BPF_READ_STR(get_task_node_name(task), &eventContext->nodename);
  get_node_info(&eventContext->node_info);

  // Command trigred event
  BPF_GET_COMM(eventContext->comm);

  // current working directory
  __s64 res = get_cwd(&eventContext->cwd);
  if (res < 0) {
    return -1;
  }

  return 0;
}

#endif