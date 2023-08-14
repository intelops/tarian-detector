#ifndef __COMMON_TASK_H__
#define __COMMON_TASK_H__

// task->real_parent->pid
static __always_inline __u32 get_task_ppid(struct task_struct *task) {
  return BPF_CORE_READ(task, real_parent, pid);
};

// task->group_leader->pid
static __always_inline __u32 get_task_glpid(struct task_struct *task) {
  return BPF_CORE_READ(task, group_leader, pid);
};

// task->start_time
static __always_inline __u64 get_task_start_time(struct task_struct *task) {
  return BPF_CORE_READ(task, start_time);
};

// task->nsproxy->uts_ns->name.nodename
static __always_inline char *get_task_node_name(struct task_struct *task) {
    return BPF_CORE_READ(task, nsproxy, uts_ns, name.nodename);
};

#endif
