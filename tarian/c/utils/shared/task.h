// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

#ifndef __UTLIS_SHARED_TASK_H__
#define __UTLIS_SHARED_TASK_H__

stain u32 get_task_ppid(struct task_struct *);
stain u32 get_task_ns_pid(struct task_struct *);
stain u32 get_task_ns_tgid(struct task_struct *);
stain u32 get_task_ns_ppid(struct task_struct *);
stain u32 get_task_pid_vnr(struct task_struct *);
stain u64 get_task_start_time(struct task_struct *);
stain u64 get_task_self_exec_id(struct task_struct *);
stain u64 get_task_parent_exec_id(struct task_struct *);
stain char *get_task_comm(struct task_struct *);
stain struct task_struct *get_task_parent(struct task_struct *);
stain struct path get_task_directory(struct task_struct *);
stain struct path get_task_executable(struct task_struct *);
stain struct nsproxy *get_task_nsproxy(struct task_struct *);

/**
 * @brief Get the process ID of a task at a specific namespace level.
 *
 * The process ID of a task is stored in the thread_pid substructure of the
 * task_struct. This substructure contains a pid_chain array, which is an
 * array of struct pid_chain. Each struct pid_chain contains a pid struct
 * and a level member, which is an integer indicating the namespace level of
 * the pid. The process ID of the task can be obtained by reading the nr member
 * of the pid struct at the namespace level of interest.
 *
 * This function retrieves the process ID of the task at a specific namespace
 * level.
 *
 * @param task The task_struct of interest.
 *
 * @return The process ID of the task at the given namespace level.
 */
stain u32 get_task_pid_vnr(struct task_struct *task) {
  unsigned int level = BPF_CORE_READ(task, thread_pid, level);

  return BPF_CORE_READ(task, thread_pid, numbers[level].nr);
};

/**
 * @brief Get the parent process ID of a task_struct.
 *
 * The parent process ID of a task_struct is stored in the real_parent member
 * of the task_struct structure. This member is a struct task_struct, which
 * contains information about the parent process of the task. The parent
 * process ID is obtained by reading the tgid member of the real_parent
 * task_struct.
 *
 * @param task The task_struct of interest.
 *
 * @return The parent process ID of the task_struct.
 */
stain u32 get_task_ppid(struct task_struct *task) {
  return BPF_CORE_READ(task, real_parent, tgid);
};

/**
 * @brief Get the start time of a task_struct.
 *
 * The start time of a task_struct is the time at which the task was created.
 * The start time is stored in the start_time member of the task_struct.
 *
 * @param task The task_struct of interest.
 *
 * @return The start time of the task_struct.
 */
stain u64 get_task_start_time(struct task_struct *task) {
  return BPF_CORE_READ(task, start_time);
}

/**
 * @brief Get the self_exec_id of a task_struct.
 *
 * The self_exec_id of a task_struct is used to identify a unique task
 * instance. It is set to the inode number of the executable when the task is
 * created.
 *
 * @param task The task_struct of interest.
 *
 * @return The self_exec_id of the task_struct.
 */
stain u64 get_task_self_exec_id(struct task_struct *task) {
  return BPF_CORE_READ(task, self_exec_id);
}

/**
 * @brief Get the parent_exec_id of a task_struct.
 *
 * The parent_exec_id of a task_struct is used to identify the executable
 * that created the task.
 *
 * @param task The task_struct of interest.
 *
 * @return The parent_exec_id of the task_struct.
 */
stain u64 get_task_parent_exec_id(struct task_struct *task) {
  return BPF_CORE_READ(task, parent_exec_id);
}

/**
 * @brief Get the process ID of a task, in its own namespace.
 *
 * The process ID of a task is stored in the pid member of the thread_pid
 * substructure of the task_struct. This function retrieves the process ID
 * of the task.
 *
 * @param task The task_struct of interest.
 *
 * @return The process ID of the task in its own namespace.
 */
stain u32 get_task_ns_pid(struct task_struct *task) {
  return get_task_pid_vnr(task);
}

/**
 * @brief Get the thread group ID of a task, in its own namespace.
 *
 * The thread group ID of a task is stored in the group_leader member of the
 * task_struct structure. This member is a struct task_struct, which contains
 * information about the group leader of the task. The thread group ID is
 * obtained by reading the pid member of the group leader task_struct.
 *
 * @param task The task_struct of interest.
 *
 * @return The thread group ID of the task in its own namespace.
 */
stain u32 get_task_ns_tgid(struct task_struct *task) {
  struct task_struct *gl = BPF_CORE_READ(task, group_leader);

  return get_task_pid_vnr(gl);
}


/**
 * @brief Get the parent process ID of a task, in its own namespace.
 *
 * The parent process ID of a task is stored in the real_parent member of the
 * task_struct structure. This member is a struct task_struct, which contains
 * information about the parent process of the task. The parent process ID is
 * obtained by reading the pid member of the real_parent task_struct.
 *
 * @param task The task_struct of interest.
 *
 * @return The parent process ID of the task in its own namespace.
 */
stain u32 get_task_ns_ppid(struct task_struct *task) {
  struct task_struct *rp = BPF_CORE_READ(task, real_parent);

  return get_task_pid_vnr(rp);
}

/**
 * @brief Get the namespace proxy of a task.
 *
 * The namespace proxy of a task is stored in the nsproxy member of the
 * task_struct structure. This member is a struct nsproxy, which contains
 * information about the namespaces of the task.
 *
 * @param task The task_struct of interest.
 *
 * @return A pointer to the task's namespace proxy.
 */
stain struct nsproxy *get_task_nsproxy(struct task_struct *task) {
  return BPF_CORE_READ(task, nsproxy);
}

/**
 * @brief Get the command name of a task.
 *
 * The command name of a task is stored in the comm member of the task_struct
 * structure. This member is a null-terminated C string that contains the
 * name of the command that started the task.
 *
 * @param task The task_struct of interest.
 *
 * @return A pointer to the task's command name.
 */
stain char *get_task_comm(struct task_struct *task) {
  return BPF_CORE_READ(task, comm);
}

/**
 * @brief Get the parent task_struct of a given task.
 *
 * This function retrieves the parent task_struct of a given task_struct.
 * The task_struct structure contains a struct task_struct member named
 * 'parent', which points to the parent task_struct.
 *
 * @param task The task_struct of interest.
 *
 * @return The parent task_struct of the given task.
 */
stain struct task_struct *get_task_parent(struct task_struct *task) {
  return BPF_CORE_READ(task, parent);
}

/**
 * @brief Get the current working directory of a task.
 * 
 * The current working directory of a task is stored in the fs substructure 
 * of the task_struct.  This path is a struct path, which is a kernel data 
 * structure similar to a file descriptor.  It contains a pointer to a 
 * struct dentry, which is the kernel equivalent of a file path.
 * 
 * @param task The task struct of interest.
 *
 * @return The current working directory path.
 */
stain struct path get_task_directory(struct task_struct *task) {
  return BPF_CORE_READ(task, fs, pwd);
}

/**
 * @brief Get the executable path of a task.
 *
 * The executable path of a task is stored in the mm substructure of the
 * task_struct.  The mm substructure contains a struct file, which is a
 * kernel data structure similar to a file descriptor.  The struct file
 * contains a struct path, which is the kernel equivalent of a file path.
 * This function retrieves the executable path of the task.
 *
 * @param task The task struct of interest.
 *
 * @return The executable path of the task.
 */
stain struct path get_task_executable(struct task_struct *task) {
  return BPF_CORE_READ(task, mm, exe_file, f_path);
}
#endif
