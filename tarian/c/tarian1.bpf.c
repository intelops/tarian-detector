// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "common.h"

// struct task_struct *task = (struct task_struct *)bpf_get_current_task();
// int ppid = BPF_CORE_READ(task, parent, pid);
// if (ppid != 525465)
//   return OK;

const event_data_t *unused __attribute__((unused));
// const enum argument_type_e unused_enum __attribute__((unused));

KPROBE("__x64_sys_execve")
int BPF_KPROBE(tdf_execve_e, struct pt_regs *regs, const char* filename) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  int ppid = BPF_CORE_READ(task, parent, pid);
  if (ppid != 525465)
    return OK;

  // if(!shouldContinue("ls", 2))
  //   return 0;

  tarian_event_t te;
  int resp = new_event(ctx, TDE_SYSCALL_EXECVE_E, &te, TDS_EXECVE_E);
  if (resp != TDC_SUCCESS) return resp;
  
  char msg[128];
  bpf_probe_read_user_str(&msg, 128, filename);

  bpf_printk("Execve e %s --%s--", msg, te.tarian->system_info.sysname);
  
  return tdf_submit_event(&te);
}

KPROBE("__x64_sys_openat")
int BPF_KPROBE(execve_e, struct pt_regs *regs) {
  // struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // int ppid = BPF_CORE_READ(task, parent, pid);
  // if (ppid != 2948263)
  //   return OK;

  if(!shouldContinue("openat", 6))
    return 0;


  bpf_override_return(ctx, 88);

  char msg[16];
  bpf_get_current_comm(&msg, 16);

  bpf_printk("Execve te: %s", msg);

  return OK;
}

KRETPROBE("__x64_sys_openat")
int BPF_KRETPROBE(execve_r, int ret) {
  // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  // int ppid = BPF_CORE_READ(task, parent, pid);
  // if (ppid != 2948263)
  //   return OK;

  char c[16];
  bpf_get_current_comm(&c, 16);

  // bpf_printk("Execve ret: %ld %s", ppid, c);

  // char *ls = "openat";
  // for(int i = 0; i < 2; i++) {
  //   if(ls[i] != c[i]) 
  //     return 0;
  // }

  if(!shouldContinue("openat", 6))
    return 0;

  sys_ctx_t sc;
  read_sys_ctx_into(&sc, ctx);
  bpf_printk("Execve BPF ret: %ld READ RET: %ld COMM: %s", ret, sc[RETURN], c);

  return 0;
}

// SEC("kprobe/__x64_sys_clone")
// int kprobe_clone(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_CLONE);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* binary file path */, ULONG_T, 0);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM2] /* binary file path */, ULONG_T, 1);
//   save_to_buffer(&p, (void *)p.sys_ctx[PARAM3] /* binary file path */, INT_T, 2);
//   save_to_buffer(&p, (void *)p.sys_ctx[PARAM4] /* binary file path */, INT_T, 3);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM5] /* binary file path */, ULONG_T, 4);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_clone")
// int kretprobe_clone(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_CLONE);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_execve")
// int kprobe_execve(struct pt_regs *ctx) {
//   trigger_data_t td = {};
//   int err = new_program(&p, ctx, SYS_ENTER_EXECVE);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (char *)p.sys_ctx[PARAM1] /* binary file path */, STR_T, 0);
//   // save_to_buffer(&p, (void *)p.sys_ctx[1] /* user command */, STR_ARR_T, 1);
//   // save_to_buffer(&p, (void *)p.sys_ctx[1] /* user command */, STR_ARR_T, 2);
//   // bpf_printk("test execve indx str %d", (int)p.cursor);
//   // save_to_buffer(&p, (void *)&(p.sys_ctx[6]), INT_T, 1);
//   // bpf_printk("test execve indx long %d", (int)p.cursor);
//   // save_to_buffer(&p, (void *)&(p.sys_ctx[6]), LONG_T, 2);
//   // bpf_printk("test execve %d %d", count++, (int)p.cursor);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_execve")
// int kretprobe_execve(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXECVE_X);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_execveat")
// int kprobe_execveat(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_EXECVEAT);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* file_descriptor */, INT_T, 0);
//   save_to_buffer(&p, (char *)p.sys_ctx[PARAM2] /* binary file path */, STR_T, 1);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM5] /* flags */, INT_T, 4);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_execveat")
// int kretprobe_execveat(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_EXECVEAT);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }
 
//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_open")
// int kprobe_open(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_OPEN);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)p.sys_ctx[PARAM1] /* filename */, STR_T, 0);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM2] /* flags */, INT_T, 1);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM3] /* mode */, INT_T, 2);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_open")
// int kretprobe_open(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_OPEN);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_openat")
// int kprobe_openat(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_OPENAT);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* directory file descriptor */, INT_T, 0);
//   save_to_buffer(&p, (void *)p.sys_ctx[PARAM2] /* filename */, STR_T, 1);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM3] /* flags */, INT_T, 2);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM4] /* mode */, UINT_T, 3);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_openat")
// int kretprobe_openat(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_OPENAT);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_openat2")
// int kprobe_openat2(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_OPENAT2);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* directory file descriptor */, INT_T, 0);
//   save_to_buffer(&p, (void *)p.sys_ctx[PARAM2] /* filename */, STR_T, 1);
//   // save_to_buffer(&p, (void *)&p.sys_ctx[PARAM3] /* how */, INT, 2); //Need to handle user defined types
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM4] /* usize */, LONG_T, 3);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_openat2")
// int kretprobe_openat2(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_OPENAT2);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_close")
// int kprobe_close(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_CLOSE);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* file descriptor */, INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_close")
// int kretprobe_close(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_CLOSE);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_read")
// int kprobe_read(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_READ);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* file descriptor */, UINT_T, 0);
//   // save_to_buffer(&p, (void *)p.sys_ctx[PARAM2]  /* buffer */, STR_T, 1);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM3] /* flags */, ULONG_T, 2);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_read")
// int kretprobe_read(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_READ);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN] /* number of bytes read */, LONG_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_readv")
// int kprobe_readv(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_READV);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* file descriptor */, ULONG_T, 0);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM3] /* vlen */, ULONG_T, 2);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_readv")
// int kretprobe_readv(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_READV);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN] /* number of bytes read */, LONG_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_write")
// int kprobe_write(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_WRITE);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* file descriptor */, UINT_T, 0);
//   // save_to_buffer(&p, (void *)p.sys_ctx[PARAM2]  /* buffer */, STR_T, 1);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM3] /* flags */, ULONG_T, 2);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_write")
// int kretprobe_write(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_WRITE);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN] /* number of bytes wrote */, LONG_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_writev")
// int kprobe_writev(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_WRITEV);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* file descriptor */, ULONG_T, 0);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM3] /* vlen */, ULONG_T, 2);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_writev")
// int kretprobe_writev(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_WRITEV);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }
//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN] /* number of bytes wrote */, LONG_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_listen")
// int kprobe_listen(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_LISTEN);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* file descriptor */, INT_T, 0);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM2] /* backlog */, INT_T, 1);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_listen")
// int kretprobe_listen(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_LISTEN);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_socket")
// int kprobe_socket(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_SOCKET);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* family */, INT_T, 0);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM2] /* type */, INT_T, 1);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM3] /* protocol */, INT_T, 2);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_socket")
// int kretprobe_socket(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_SOCKET);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_accept")
// int kprobe_accept(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_ACCEPT);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* file descriptor */, INT_T, 0);
//   // save_to_buffer(&p, (void *)&p.sys_ctx[PARAM2] /* type */, INT_T, 1);
//   save_to_buffer(&p, (void *)p.sys_ctx[PARAM3] /* upeer_addrlen */, INT_T, 2);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_accept")
// int kretprobe_accept(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_ACCEPT);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_bind")
// int kprobe_bind(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_BIND);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* file descriptor */, INT_T, 0);
//   // save_to_buffer(&p, (void *)&p.sys_ctx[PARAM2] /* type */, INT_T, 1);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM3] /* upeer_addrlen */, INT_T, 2);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_bind")
// int kretprobe_bind(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_BIND);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kprobe/__x64_sys_connect")
// int kprobe_connect(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_ENTER_CONNECT);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM1] /* file descriptor */, INT_T, 0);
//   // save_to_buffer(&p, (void *)&p.sys_ctx[PARAM2] /* type */, INT_T, 1);
//   save_to_buffer(&p, (void *)&p.sys_ctx[PARAM3] /* upeer_addrlen */, INT_T, 2);

//   events_ringbuf_submit(&p);
//   return OK;
// }

// SEC("kretprobe/__x64_sys_connect")
// int kretprobe_connect(struct pt_regs *ctx) {
//   program_data_t p = {};
//   int err = new_program(&p, ctx, SYS_EXIT_CONNECT);
//   if (err != OK) {
//     dropped++;
//     return err;
//   }

//   save_to_buffer(&p, (void *)&p.sys_ctx[RETURN], INT_T, 0);

//   events_ringbuf_submit(&p);
//   return OK;
// }