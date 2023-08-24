#ifndef __UTLIS_C_COMMON_TYPES_H__
#define __UTLIS_C_COMMON_TYPES_H__

#include "index.h"

typedef struct {
  __u8 sysname[65];
  __u8 nodename[65];
  __u8 release[65];
  __u8 version[65];
  __u8 machine[65];
  __u8 domainname[65];
} node_info_t;

typedef struct {
  __s32 mount_id;          // mount id
  __u32 mount_ns_id;       // mount namespace id
  __u8 mount_devname[256]; // mount device name
} mount_info_t;

typedef struct __attribute__((__packed__)) event_context {
  __u64 ts;         // boot time
  __u64 start_time; // start time

  __u32 pid;  // process id
  __u32 tgid; // thread group id

  __u32 ppid;  // parent process id
  __u32 glpid; // group leader process id

  __u32 uid; // user id
  __u32 gid; // group id

  __u8 comm[TASK_COMM_LEN]; // command
  __u8 cwd[32];             // current working directory

  __u64 cgroup_id; // cgroup id

  node_info_t node_info; // node/system information
  mount_info_t mount_info; // mount information
} event_context_t;

typedef unsigned long sys_args_t[5];

#endif