#ifndef UTLIS_SHARED_TASK_H
#define UTLIS_SHARED_TASK_H

// function  definitions
stain u32 get_task_ppid(struct task_struct *);
stain u32 get_task_ns_pid(struct task_struct *);
stain u32 get_task_ns_tgid(struct task_struct *);
stain u32 get_task_ns_ppid(struct task_struct *);
stain u32 get_task_pid_vnr(struct task_struct *);
stain u64 get_task_start_time(struct task_struct *);
stain struct nsproxy *get_task_nsproxy(struct task_struct *);

// task->thread_pid->numbers[level].nr
stain u32 get_task_pid_vnr(struct task_struct *task){
  unsigned int level = BPF_CORE_READ(task, thread_pid, level);

  return BPF_CORE_READ(task, thread_pid, numbers[level].nr);
};

// task->real_parent->pid
stain u32 get_task_ppid(struct task_struct *task) {
  return BPF_CORE_READ(task, real_parent, tgid);
};

// task->start_time
stain u64 get_task_start_time(struct task_struct *task) {
  return BPF_CORE_READ(task, start_time);
};

stain u64 get_task_self_exec_id(struct task_struct *task) {
  return BPF_CORE_READ(task, self_exec_id);
};

stain u64 get_task_parent_exec_id(struct task_struct *task) {
  return BPF_CORE_READ(task, parent_exec_id);
};

stain u32 get_task_ns_pid(struct task_struct *task) {
  return get_task_pid_vnr(task);
};

stain u32 get_task_ns_tgid(struct task_struct *task) {
  struct task_struct *gl = BPF_CORE_READ(task, group_leader);
  
  return get_task_pid_vnr(gl);
};

stain u32 get_task_ns_ppid(struct task_struct *task){
  struct task_struct *rp = BPF_CORE_READ(task, real_parent);

  return get_task_pid_vnr(rp);
};

// task->nsproxy
stain struct nsproxy *get_task_nsproxy(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy);
};

stain char *get_task_comm(struct task_struct *task) {
  return BPF_CORE_READ(task, comm);
}

stain struct task_struct *get_task_parent(struct task_struct *task) {
  return BPF_CORE_READ(task, parent);
}

#endif
