#ifndef __UTILS_C_CONTEXT_H__
#define __UTILS_C_CONTEXT_H__

#include "index.h"

// func definitions
static __always_inline int init_context(event_context_t *);
static __always_inline int set_context(event_context_t *, struct task_struct *);
static __always_inline node_info_t get_node_info(struct task_struct *);
static __always_inline mount_info_t get_mount_info(struct task_struct *);

static __always_inline int init_context(event_context_t *eventContext) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  return set_context(eventContext, task);
}

static __always_inline int set_context(event_context_t *e,
                                       struct task_struct *task) {
  // system boot time
  e->ts = bpf_ktime_get_ns();

  // thread start time
  e->start_time = get_task_start_time(task);

  // process Id and thread Group Id
  get_pid_tgid(&e->pid, &e->tgid);

  // real_parent process id
  e->ppid = get_task_ppid(task);

  // group leader process id
  e->glpid = get_task_glpid(task);

  // user Id and group Id
  get_uid_gid(&e->uid, &e->gid);

  // Command trigred event
  BPF_GET_COMM(e->comm);

  // current working directory
  __s64 res = get_cwd(&e->cwd);
  if (res < 0) {
    return -1;
  }

  // node information
  e->node_info = get_node_info(task);

  // mount information
  e->mount_info = get_mount_info(task);

  e->cgroup_id = bpf_get_current_cgroup_id();

  return 0;
}

// task->nsproxy->uts_ns->name
static __always_inline node_info_t get_node_info(struct task_struct *task) {

  struct uts_namespace *uts_ns = get_uts_ns(get_task_nsproxy(task));

  node_info_t node_info;
  BPF_CORE_READ_INTO(&node_info, uts_ns, name);

  return node_info;
}

// task->nsproxy->mnt_ns->root->*
static __always_inline mount_info_t get_mount_info(struct task_struct *task) {
  mount_info_t mount_info;

  mount_info.mount_id = get_mts_id(get_task_nsproxy(task));
  mount_info.mount_ns_id = get_uts_ns_id(get_task_nsproxy(task));

  BPF_READ_STR((const char *)get_mts_devname(get_task_nsproxy(task)),
               &mount_info.mount_devname);

  return mount_info;
}

#endif