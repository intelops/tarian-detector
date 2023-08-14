#ifndef __COMMON_TYPES_H__
#define __COMMON_TYPES_H__

#include "constants.h"

typedef struct __attribute__((__packed__)) event_context {
  
  __u64 ts;         // boot time
  __u64 start_time; // start time

  __u32 pid;  // process id
  __u32 tgid; // thread group id

  __u32 ppid;  // parent process id
  __u32 glpid; // group leader process id

  __u32 uid; // user id
  __u32 gid; // group id

  __u8 nodename[65];        // nodename
  __u8 comm[TASK_COMM_LEN]; // command
  __u8 cwd[32];             // current working directory
} event_context_t;

typedef struct args {
  unsigned long args[6];
} args_t;

#endif