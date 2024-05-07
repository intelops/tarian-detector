// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

#ifndef __UTILS_META_H__
#define __UTILS_META_H__

#include "index.h"

stain int prepare_tarian_event(tarian_event_t *te, struct pt_regs *ctx, enum tarian_events_e event);
stain int can_event_proceed(tarian_event_t *te);
stain int init_tarian_event(tarian_event_t *te, struct pt_regs *ctx, int event);
stain int init_tarian_meta_data(tarian_meta_data_t *te, int event, int syscall, struct task_struct *task);
stain int init_event_meta_data(event_meta_data_t *emd, int event, int syscall, struct task_struct *task);
stain int init_task_meta_data(task_meta_data_t *tmd, struct task_struct *task);
stain int init_system_info(system_info_t *si, struct task_struct *task);
stain int write_cwd_and_exe_to_buffer(tarian_event_t *te);

/**
 * @brief Prepare a tarian event
 *
 * Prepares a tarian event by checking if it can be processed,
 * initializing the event metadata and add the current working directory
 * and executable to the event buffer.
 *
 * @param te Pointer to the tarian event structure
 * @param ctx System call context
 * @param event Tarian event type
 * 
 * @return `TDC_SUCCESS` if the event was successfully initialized,
 *         otherwise a status code indicating the error
 */
stain int prepare_tarian_event(tarian_event_t *te, struct pt_regs *ctx, enum tarian_events_e event) {
  // Check if event can be processed
  int status = can_event_proceed(te);
  if (status != TDC_SUCCESS) {
    return status;
  }

  // Initialize tarian event
  status = init_tarian_event(te, ctx, event);
  if (status != TDC_SUCCESS) {
    return status;
  }

  // Get system call id
  int syscall;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
  syscall = get_syscall_id(te->ctx);
#else
  struct pt_regs *regs = PT_REGS_SYSCALL_REGS(te->ctx);
  syscall = get_syscall_id(regs);
#endif

  // Initialize tarian metadata
  status = init_tarian_meta_data(te->tarian, event, syscall, te->task);
  if (status != TDC_SUCCESS) {
    return status;
  }

  // Initialize cwd and executable
  status = write_cwd_and_exe_to_buffer(te);
  if (status != TDC_SUCCESS) {
    return status;
  }

  // Print the event
  print_event(te);

  return TDC_SUCCESS;
}

/**
 * @brief Check if the event can be processed
 *
 * Checks if the event should be processed based on the user defined
 * filters in the kernel. If the event does not qualify, it is dropped
 * and a success status is returned with the event code set to
 * `TDC_FILTERED_OUT`.
 *
 * @param te Pointer to the tarian event structure
 * 
 * @return `TDC_SUCCESS` if the event can proceed, `TDC_FILTERED_OUT` otherwise
 */
stain int can_event_proceed(tarian_event_t *te) {
  /* Check if the event qualifies based on user defined filters */
  if (!does_event_qualify()) {
    return TDC_FILTERED_OUT;
  }

  return TDC_SUCCESS;
}


/**
 * @brief Initialize tarian event structure
 *
 * This function initializes the tarian event structure with the provided system
 * call context and event type.
 * 
 * @param te Pointer to the tarian event structure
 * @param ctx System call context
 * @param event Tarian event type
 * 
 * @return `TDC_SUCCESS` if the event was successfully initialized,
 *         otherwise a status code indicating the error
 */
stain int init_tarian_event(tarian_event_t *te, struct pt_regs *ctx, int event) {
  te->ctx = ctx;
  te->task = (struct task_struct *)bpf_get_current_task();

  /* Reserve space for tarian event */
  int status = tdf_reserve_space(&te->buf);
  if (status != TDC_SUCCESS) {
    return status;
  }

  /* Initialize tarian metadata pointer */
  te->tarian = (tarian_meta_data_t *)te->buf.data;
  te->buf.pos = sizeof(tarian_meta_data_t);

  /* Reserve scratch space for the event */
  status = tdf_scratch_space(te);
  if (status != TDC_SUCCESS) {
    return status;
  }

  return TDC_SUCCESS;
}

/**
 * @brief Initialize tarian metadata structure
 *
 * This function initializes the tarian metadata structure with the
 * provided event, system call, and task structure. The tarian metadata
 * structure contains event metadata and system information.
 *
 * @param tmd Pointer to the tarian metadata structure
 * @param event Tarian event type
 * @param syscall System call id
 * @param task Pointer to the task structure
 * 
 * @return `TDC_SUCCESS` if the tarian metadata was successfully initialized,
 *         otherwise a status code indicating the error
 */
stain int init_tarian_meta_data(tarian_meta_data_t *tmd, int event, int syscall, struct task_struct *task) {
  int status = init_event_meta_data(&tmd->meta_data, event, syscall, task);
  if (status != TDC_SUCCESS) {
    return status;
  }

  return init_system_info(&tmd->system_info, task);
}

/**
 * @brief Initialize event metadata structure
 *
 * Initializes the event metadata structure with the provided event,
 * system call, and task structure.
 *
 * @param emd Pointer to the event metadata structure to be initialized
 * @param event Tarian event type
 * @param syscall System call id
 * @param task Pointer to the task structure
 *
 * @return `TDC_SUCCESS` if the event metadata was successfully initialized,
 *         otherwise a status code indicating the error
 */
stain int init_event_meta_data(event_meta_data_t *emd, int event, int syscall, struct task_struct *task) {
  emd->event = event;
  emd->nparams = 0;
  emd->ts = bpf_ktime_get_ns();
  emd->syscall = syscall;
  emd->processor = (uint16_t)bpf_get_smp_processor_id();

  return init_task_meta_data(&emd->task, task);
}

/**
 * @brief Initialize task metadata structure
 *
 * This function initializes the task metadata structure with the provided task
 * structure.
 *
 * @param tmd Pointer to the task metadata structure to be initialized
 * @param task Pointer to the task structure
 * 
 * @return `TDC_SUCCESS` if the event metadata was successfully initialized,
 *         otherwise a status code indicating the error
 */
stain int init_task_meta_data(task_meta_data_t *tmd, struct task_struct *task) {
  tmd->start_time = get_task_start_time(task);

  /**
   * As seen in Tracee
   * https://github.com/aquasecurity/tracee/blob/935ad012f0a040bb04b7f3b0c574a36a4e9cc909/pkg/ebpf/c/common/context.h#L125-L127
   */
  u64 ptid = bpf_get_current_pid_tgid();
  tmd->host_tgid = ptid;
  tmd->host_pid = ptid >> 32;

  tmd->host_ppid = get_task_ppid(task);

  /**
   * This is not a mistake. Followed this from tracee.
   * https://github.com/aquasecurity/tracee/blob/935ad012f0a040bb04b7f3b0c574a36a4e9cc909/pkg/ebpf/c/common/context.h#L33C1-L34C43
   */
  tmd->pid = get_task_ns_tgid(task);
  tmd->tgid = get_task_ns_pid(task);

  tmd->ppid = get_task_ns_ppid(task);

  u64 guid = bpf_get_current_uid_gid();
  tmd->uid = guid;
  tmd->gid = guid >> 32;

  tmd->cgroup_id = bpf_get_current_cgroup_id();

  tmd->mount_ns_id = get_mnt_ns_id(get_task_nsproxy(task));
  tmd->pid_ns_id = get_pid_ns_id(get_task_nsproxy(task));

  tmd->exec_id = getExecId(tmd->host_pid, task);
  tmd->parent_exec_id = getParentExecId(tmd->host_ppid, task);

  int status = bpf_get_current_comm(tmd->comm, TASK_COMM_LEN);
  if (status != 0) {
    return TDC_FAILURE;
  }

  return TDC_SUCCESS;
}

/**
 * @brief Initialize system info
 *
 * Fills the system info struct with the system name as seen in the
 * uts namespace of the task.
 *
 * @param si Pointer to the system info struct to be filled
 * @param task Pointer to the task struct from which to get the uts namespace
 * 
 * @return `TDC_SUCCESS` if the event metadata was successfully initialized,
 *         otherwise a status code indicating the error
 */
stain int init_system_info(system_info_t *si, struct task_struct *task) {
  struct uts_namespace *uts_ns = get_uts_ns(get_task_nsproxy(task));

  int status = BPF_CORE_READ_INTO(si, uts_ns, name);
  if (status < 0) {
    return TDC_FAILURE;
  }

  return TDC_SUCCESS;
}

/**
 * @brief Initialize current working directory and executable path
 *
 * This function retrieves the current working directory and executable
 * path of the task and stores them in the tarian event buffer.
 *
 * @param te Pointer to the tarian event structure to be filled
 *
 * @return `TDC_SUCCESS` if the event metadata was successfully initialized,
 *         otherwise a status code indicating the error
 */
stain int write_cwd_and_exe_to_buffer(tarian_event_t *te) {
  // Get directory
  struct path dpath = get_task_directory(te->task);
  path_info_t dir = get__d_path(&dpath, te->scratch);

  /* Write the directory path to the event buffer */
  int ret = write_str(te->buf.data, &te->buf.pos, (unsigned long)dir.data, dir.len, KERNEL);
  if (ret == -1) {
    return TDC_FAILURE;
  }

  /* Set the directory pointer to the start of the directory in the event buffer */
  te->directory.data = &(te->buf.data[SAFE_ACCESS_PARAM((te->buf.pos - dir.len))]);
  te->directory.len = dir.len;

  // Get executable
  struct path epath = get_task_executable(te->task);
  path_info_t exe = get__d_path(&epath, te->scratch);

  /* Write the executable path to the event buffer */
  ret = write_str(te->buf.data, &te->buf.pos, (unsigned long)exe.data, exe.len, KERNEL);
  if (ret == -1) {
    return TDC_FAILURE;
  }

  /* Set the executable pointer to the start of the executable in the event buffer */
  te->executable.data = &(te->buf.data[SAFE_ACCESS_PARAM((te->buf.pos - exe.len))]);
  te->executable.len = exe.len;

  return TDC_SUCCESS;
}

#endif