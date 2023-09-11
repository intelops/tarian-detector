// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "includes.h"

// data gathered by this program
struct event_data {
  event_context_t eventContext;

  int id;

  int fd;     // File descriptor
  size_t len; // Number of bytes
  unsigned int flags;

  int msg_namelen;            // length of destination address
  __u8 msg_name[64];          // buffer for destination address
  __kernel_size_t msg_iovlen; // length of the message

  int ret;
};

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));

// ringbuffer map definition
BPF_RINGBUF_MAP(sendmsg_event_map);

// entry
SEC("kprobe/__x64_sys_sendmsg")
int kprobe_sendmsg_entry(struct pt_regs *ctx) {
  struct event_data *ed;
  sys_args_t sys_args;
  struct user_msghdr user_msg;
  struct iovec iov;

  // allocate space for an accept_event_map in map.
  ed = BPF_RINGBUF_RESERVE(sendmsg_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 0;

  // sets the context
  init_context(&ed->eventContext);

  read_sys_args_into(&sys_args, ctx);

  // Read the file descriptor argument
  ed->fd = (int)sys_args[0];

  // Read the message header
  struct user_msghdr *user_msg_ptr = (struct user_msghdr *)sys_args[1];
  bpf_probe_read(&user_msg, sizeof(user_msg), user_msg_ptr);
  

  ed->msg_namelen = user_msg.msg_namelen;
  bpf_probe_read(ed->msg_name, sizeof(ed->msg_name), user_msg.msg_name);


  // Read Message Data (for first buffer only)
  if (user_msg.msg_iov) {
    bpf_probe_read(&iov, sizeof(iov), user_msg.msg_iov);
    ed->len = iov.iov_len;
  }

  // Read the flags
  ed->flags = (int)sys_args[2];

  // pushes the information to ringbuf accept_event_map map
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
}

// exit
SEC("kretprobe/__x64_sys_sendmsg")
int kretprobe_sendmsg_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an accept_event_map in map.
  ed = BPF_RINGBUF_RESERVE(sendmsg_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  init_context(&ed->eventContext);

  // return value - int
  ed->ret = (int)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf accept_event_map map
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
