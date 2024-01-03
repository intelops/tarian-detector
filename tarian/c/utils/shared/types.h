#ifndef __UTLIS_SHARED_TYPES_H__
#define __UTLIS_SHARED_TYPES_H__

#include "index.h"

typedef struct data_heap {
  u8 buf[MAX_PERCPU_BUFSIZE];
} buf_t;

typedef unsigned long sys_ctx_t[MAX_ARGS];

typedef struct {
  u8 sysname[MAX_NODE_FIELD_SIZE];    /* operating system */
  u8 nodename[MAX_NODE_FIELD_SIZE];   /* hostname */
  u8 release[MAX_NODE_FIELD_SIZE];    /* os version */
  u8 version[MAX_NODE_FIELD_SIZE];    /* additional version info of os*/
  u8 machine[MAX_NODE_FIELD_SIZE];    /* architecture of system */
  u8 domainname[MAX_NODE_FIELD_SIZE]; /* domain of system */
} node_info_t;                        /* 390B */

typedef struct __attribute__((__packed__)) task_context {
  u64 start_time; /* task's start time */

  u32 host_pid; /* task's process id */
  u32 host_tgid; /* task's thread group id */

  u32 host_ppid; /* task's parent process id */

  u32 pid;  /* task's namespace process id */
  u32 tgid; /* task's namespace thread group id */

  u32 ppid;  /* task's parent process id */

  u32 uid; /* task's effective user id */
  u32 gid; /* task's effective group id */

  u64 cgroup_id; /* task's control group id */

  u64 mount_ns_id; /* task's mount name space id */
  u64 pid_ns_id;   /* task's pid name space id */

  u64 exec_id;
  u64 parent_exec_id;
  
  u64 eexec_id;
  u64 eparent_exec_id;

  u8 comm[TASK_COMM_LEN]; /* task's process name*/
  u8 cwd[MAX_STRING_SIZE]; /* current working directory of task */
} task_context_t;           /* 4176B */

typedef struct __attribute__((__packed__)) event_context {
  u64 ts; /* event timestamp */

  task_context_t task;

  u32 event_id;   /* event id associated with the event */
  s32 syscall; /* syscall id (system call) associated with the event */

  u16 processor_id; /* processor id where the event was processed */
} event_context_t; /* 4194B */

typedef struct __attribute__((__packed__)) syscall_buffer {
  u8 num_fields;         /* no of fields; */
  u64 field_types;      /* bitmask representing the XOR of field types */
  u8 data[SYS_BUF_SIZE]; /* buffer for storing  syscall information(arguments, return value)*/
} syscall_buffer_t;     /* 10249B */

typedef struct __attribute__((__packed__)) event_data {
  event_context_t context;
  syscall_buffer_t buf;
  node_info_t system_info; /* system information */
} event_data_t;            /* 14833B or 15KB */

typedef struct program_data {
  event_data_t *event;
  sys_ctx_t sys_ctx; /* context of the syscall */
  u32 cursor;       /* cursor indicating the current position of data in syscall_buffer*/
  struct task_struct *task /* pointer to the task_struct representing the task */;
  void *ctx;      /* pointer to register context */
} program_data_t; /* 88B */

#endif