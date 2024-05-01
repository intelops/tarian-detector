// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

#ifndef __UTILS_SHARED_TYPES_H__
#define __UTILS_SHARED_TYPES_H__

/**
 * @struct per_cpu_buffer
 * @brief A structure to represent a per CPU buffer.
 *
 * This structure is used to create a buffer for each CPU.
 *
 * - `data`: an array of type uint8_t to hold the buffer. The total size of the
 * buffer is 32KB.
 */
typedef struct per_cpu_buffer {
  uint8_t data[MAX_CPU_BUFFER_SIZE];
} per_cpu_buffer_t;

/**
 * @struct path_data
 * @brief A structure to hold path information.
 *
 * This structure is used to store the path string and its length that a
 * function reads from a struct path.
 *
 * - `len`: an integer to hold the length of the path.
 * - `data`: a pointer to hold the path string.
 */
typedef struct path_data {
  int32_t len;
  uint8_t *data;
} path_data_t;

/**
 * @struct scratch_space
 * @brief A structure to represent a scratch space.
 *
 * This structure is used to create a scratch space of size
 * MAX_SCRATCH_SPACE_SIZE. The total size of the scratch
 * space is 8KB.
 *
 * - `pos`: an integer to hold the current empty position of the buffer.
 * - `data`: an array of type uint8_t to hold the data.
 */
typedef struct scratch_space {
  uint64_t pos;
  uint8_t data[MAX_SCRATCH_SPACE_SIZE];
} scratch_space_t;

/**
 * @struct event_buffer
 * @brief A structure to hold event data.
 *
 * This structure is used to store the event data.
 *
 * - `reserved_space`: an integer to hold the length of the 'data' array.
 * - `pos`: an integer to hold the current empty position of byte in the
 *   'data' array.
 * - `data`: a pointer to hold the syscall data.
 */
typedef struct __attribute__((__packed__)) event_buffer {
  u64 reserved_space;
  u64 pos;
  u8 *data;
} event_buffer_t;

/**
 * @struct system_info_t
 * @brief A structure to hold system information.
 *
 *
 * - `sysname`: the name of the operating system.
 * - `nodename`: the name of the node.
 * - `release`: the release of the operating system.
 * - `version`: the version information.
 * - `machine`: the machine type.
 * - `domainname`: the domain name.
 */
typedef struct new_utsname system_info_t;


/**
 * @struct task_meta_data
 * @brief A structure to hold task metadata.
 *
 * This structure is used to store the metadata associated with a task.
 *
 * - `start_time`: the task's start time.
 * - `host_pid`: the task's process id.
 * - `host_tgid`: the task's thread group id.
 * - `host_ppid`: the task's parent process id.
 * - `pid`: the task's namespace process id.
 * - `tgid`: the task's namespace thread group id.
 * - `ppid`: the task's parent process id.
 * - `uid`: the task's user id.
 * - `gid`: the task's group id.
 * - `cgroup_id`: the task's control group id.
 * - `mount_ns_id`: the task's mount name space id.
 * - `pid_ns_id`: the task's pid name space id.
 * - `exec_id`: a user defined execution id.
 * - `parent_exec_id`: a user defined parent execution id.
 * - `comm`: the task's process name.
 */
typedef struct __attribute__((__packed__)) task_meta_data {
  u64 start_time;
  u32 host_pid;
  u32 host_tgid;
  u32 host_ppid;
  u32 pid;
  u32 tgid;
  u32 ppid;
  u32 uid;
  u32 gid;
  u64 cgroup_id;
  u64 mount_ns_id;
  u64 pid_ns_id;
  u64 exec_id;
  u64 parent_exec_id;
  u8 comm[TASK_COMM_LEN];
} task_meta_data_t;

/**
 * @struct event_meta_data
 * @brief A structure to hold event metadata.
 *
 * This structure is used to store the metadata associated with an event.
 *
 * - `event`: the event id associated with the event.
 * - `nparams`: the number of parameters associated with the event.
 * - `syscall`: the system call id (if applicable) associated with the event.
 * - `ts`: the event timestamp.
 * - `processor`: the processor id where the event was processed.
 * - `task`: the event's task metadata.
 */
typedef struct __attribute__((__packed__)) event_meta_data {
  s32 event;
  u8 nparams;
  s32 syscall;
  u64 ts;
  u16 processor;
  task_meta_data_t task;
} event_meta_data_t;

/**
 * @struct tarian_meta_data
 * @brief A structure to hold metadata about the event.
 *
 * This structure is used to store the metadata associated with an event.
 *
 * - `meta_data`: the event's metadata.
 * - `system_info`: the system information associated with the event.
 */
typedef struct __attribute__((__packed__)) tarian_meta_data {
  event_meta_data_t meta_data;
  system_info_t system_info;
} tarian_meta_data_t;

/**
 * @struct tarian_event
 * @brief A structure to hold an event.
 *
 * This structure is used to store an event and its metadata.
 *
 * - `allocation_mode`: the mode used to allocate the buffer.
 * - `task`: a pointer to the task_struct representing the task.
 * - `ctx`: a pointer to the register context.
 * - `tarian`: a pointer to the tarian metadata associated with the event.
 * - `buf`: an event_buffer_t struct containing the event buffer.
 * - `scratch`: a pointer to the scratch space associated with the event (if any).
 */
typedef struct event {
  /** 1 - buf on per cpu array for perf event
    * 2 - ringbuf map
    * 3 - buf on per cpu array for ringbuf
  */
  u8 allocation_mode;
  struct task_struct *task;
  struct pt_regs *ctx;
  tarian_meta_data_t *tarian;
  event_buffer_t buf;
  scratch_space_t *scratch;
} tarian_event_t;

/**
 * @struct tarian_stats
 * @brief Structure to hold statistics for the Tarian detector hook.
 *
 * This structure contains counts of various Tarian scenarios:
 *
 * - `n_trgs`: Count of times the Tarian detector hook was triggered, whether
 *   dropped or successfully sent to userspace.
 * - `n_trgs_sent`: Count of successfully sent triggers to userspace.
 * - `n_trgs_dropped`: Count of dropped triggers not sent to userspace.
 * - `n_trgs_dropped_max_map_capacity`: Count of dropped triggers due to a
 *   full map capacity.
 * - `n_trgs_dropped_max_buffer_size`: Count of triggers with insufficient
 *   buffer size.
 * - `n_trgs_read_error`: Count of events with bpf_probe_read_* failures.
 * - `n_trgs_filter_drop`: Count of dropped triggers due to a filter match.
 * - `n_trgs_unknown`: Count of untracked scenarios.
 */
typedef struct tarian_stats {
  u64 n_trgs;
  u64 n_trgs_sent;
  u64 n_trgs_dropped;
  u64 n_trgs_dropped_max_map_capacity;
  u64 n_trgs_dropped_max_buffer_size;
  u64 n_trgs_read_error;
  u64 n_trgs_filter_drop;
  u64 n_trgs_unknown;
} tarian_stats_t;

#endif