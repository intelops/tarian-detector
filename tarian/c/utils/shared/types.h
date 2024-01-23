#ifndef __UTLIS_SHARED_TYPES_H__
#define __UTLIS_SHARED_TYPES_H__

#include "index.h"

typedef struct {
  uint8_t data[MAX_BUFFER_SIZE];
} per_cpu_buffer_t;

typedef struct {
  int len;
  u8 *data;
} path_info_t;

typedef struct {
  uint8_t data[MAX_SCRATCH_SPACE];
  uint64_t pos;
} scratch_space_t;

typedef struct __attribute__((__packed__)) event_buffer {
  u64 reserved_space; /* length of 'data' array; */
  u64 pos;           /* current empty position of byte in data array */
  u8 *data;           /* array for storing syscall data*/
} event_buffer_t;   /* 20B */

typedef struct node_meta_data {
  u8 sysname[MAX_NODE_FIELD_SIZE];    /* operating system */
  u8 nodename[MAX_NODE_FIELD_SIZE];   /* hostname */
  u8 release[MAX_NODE_FIELD_SIZE];    /* os version */
  u8 version[MAX_NODE_FIELD_SIZE];    /* additional version info of os*/
  u8 machine[MAX_NODE_FIELD_SIZE];    /* architecture of system */
  u8 domainname[MAX_NODE_FIELD_SIZE]; /* domain of system */
} node_meta_data_t;                   /* 390B */

typedef struct __attribute__((__packed__)) task_meta_data {
  u64 start_time; /* task's start time */

  u32 host_pid;  /* task's process id */
  u32 host_tgid; /* task's thread group id */

  u32 host_ppid; /* task's parent process id */

  u32 pid;  /* task's namespace process id */
  u32 tgid; /* task's namespace thread group id */

  u32 ppid; /* task's parent process id */

  u32 uid; /* task's user id */
  u32 gid; /* task's group id */

  u64 cgroup_id; /* task's control group id */

  u64 mount_ns_id; /* task's mount name space id */
  u64 pid_ns_id;   /* task's pid name space id */

  u64 exec_id;        /* user defined: execution id*/
  u64 parent_exec_id; /* user defined: parent execution id*/

  u8 comm[TASK_COMM_LEN];  /* task's process name*/
  u8 cwd[MAX_TARIAN_PATH];
} task_meta_data_t;        /* 4176B */

typedef struct __attribute__((__packed__)) event_meta_data {
  s32 event;      /* event id associated with the event */
  u8 nparams;       /* no of params*/
  s32 syscall;       /* syscall id (system call) associated with the event */
  u64 ts; /* event timestamp */
  u16 processor;  /* processor id where the event was processed */
  task_meta_data_t task; /* event's task meta data */
} event_meta_data_t; /* 4194B */

typedef struct __attribute__((__packed__)) tarian_meta_data {
  event_meta_data_t meta_data;
  node_meta_data_t system_info; /* system information */
} tarian_meta_data_t;           /* 14833B or 15KB */

typedef struct event {
  u8 allocation_mode; /* 1 - buf on per cpu array for perf event 2 - ringbuf map 3 - buf on per cpu array for ringbuf */
  struct task_struct *task /* pointer to the task_struct representing the task */;
  struct pt_regs *ctx;      /* pointer to register context */
  tarian_meta_data_t *tarian;
  event_buffer_t buf;
} tarian_event_t; /* 88B */

typedef struct tarian_stats {
  u64 n_trgs; /* count of times the tarian detector hook was triggered, whether
                 dropped or successfully sent to userspace */
  u64 n_trgs_sent;    /* count of successfully sent triggers to userspace */
  u64 n_trgs_dropped; /* count of dropped triggers not sent to userspace */

  u64 n_trgs_dropped_max_map_capacity; /* count of dropped triggers due to a
                                          full map capacity */

  u64 n_trgs_max_buffer_size; /* count of triggers with insufficient buffer size
                               */
} tarian_stats_t;

#endif