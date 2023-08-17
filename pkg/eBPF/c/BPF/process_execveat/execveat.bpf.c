// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "headers.h"

// data gathered by this program
struct event_data {
  event_context_t eventContext;

  int id;
  int fd;
  int flags;
  int ret;

  __u8 binary_filepath[MAX_STRING_SIZE];
  __u8 user_comm[MAX_LOOP][MAX_STRING_SIZE];
  __u8 env_vars[MAX_LOOP][MAX_STRING_SIZE];
};

#ifdef BTF_SUPPORTED

#define READ_KERN(ptr)                                    \
    ({                                                    \
        typeof(ptr) _val;                                 \
        __builtin_memset((void *)&_val, 0, sizeof(_val)); \
        bpf_core_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                             \
    })
#else

#define READ_KERN(ptr)                                     \
    ({                                                     \
        typeof(ptr) _val;                                  \
        __builtin_memset((void *)&_val, 0, sizeof(_val));  \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                              \
    })
#endif

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(event);

// entry
SEC("kprobe/__x64_sys_execveat")
int kprobe_execveat_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an event in map.
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 0;

  // sets the context
  set_context(&ed->eventContext);

  struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);

  ed->fd = (int)PT_REGS_PARM1_CORE(ctx2);

  // binary File path
  __s64 res = BPF_READ_STR((char *)PT_REGS_PARM1_CORE(ctx2), &ed->binary_filepath);
  if (res < 0) {
    BPF_RINGBUF_DISCARD(ed);
    return -1;
  }

  // user command
  read_str_arr_to_ptr((const char *const *)PT_REGS_PARM2_CORE(ctx2),
                      ed->user_comm);

  // environment variables
  read_str_arr_to_ptr((const char *const *)PT_REGS_PARM3_CORE(ctx2),
                      ed->env_vars);

  ed->flags = (int)PT_REGS_PARM5_CORE(ctx2);


  bpf_printk("test entry: %d %d %d %d %d", ed->eventContext.pid ,PT_REGS_PARM1_CORE(ctx2), ed->fd, PT_REGS_PARM5_CORE(ctx2), ed->flags);
  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// exit
SEC("kretprobe/__x64_sys_execveat")
int kretprobe_execveat_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an event in map.
  ed = BPF_RINGBUF_RESERVE(event, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  set_context(&ed->eventContext);

  ed->ret = (int)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf event mamp
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
