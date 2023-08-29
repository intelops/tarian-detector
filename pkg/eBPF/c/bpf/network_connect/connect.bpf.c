// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

//go:build ignore

#include "includes.h"

// data gathered by this program
struct event_data {
  event_context_t eventContext;

  int id;
  int fd;      // File descriptor
  int addrlen; // Address length
  int ret;
  __u16 sa_family; // Socket address family
  __u16 port;      // Port number
  struct {
    __be32 s_addr; // IPv4 address
  } v4_addr;
  struct {
    __u8 s6_addr[16]; // IPv6 address
  } v6_addr;
  struct {
    char path[MAX_UNIX_PATH]; // UNIX socket path
  } unix_addr;
  __u32 padding; // Padding for alignment
};

// Force emits struct event_data into the elf
const struct event_data *unused __attribute__((unused));
static inline __u16 my_ntohs(__u16 port) { return (port >> 8) | (port << 8); }
// ringbuffer map definition
BPF_RINGBUF_MAP(connect_event_map);

// entry
SEC("kprobe/__x64_sys_connect")
int kprobe_connect_entry(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an connect_event_map in map.
  ed = BPF_RINGBUF_RESERVE(connect_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 0;

  // sets the context
  init_context(&ed->eventContext);

  sys_args_t sys_args;
  read_sys_args_into(&sys_args, ctx);

  // Read the domain argument
  ed->fd = (int)sys_args[0];

  // Read the type argument
  struct sockaddr *uservaddr_ptr = (struct sockaddr *)sys_args[1];

  // Read the protocol argument

  ed->addrlen = (int)sys_args[2];
  BPF_READ(uservaddr_ptr, &ed->sa_family);
  // Handle data based on the socket type
  switch (ed->sa_family) {
  case AF_INET: {
    struct sockaddr_in v4;
    BPF_READ(uservaddr_ptr, &v4);
    ed->v4_addr.s_addr = v4.sin_addr.s_addr;
    ed->port = my_ntohs(v4.sin_port); // Convert from network to host byte order
  } break;
  case AF_INET6: {
    struct sockaddr_in6 v6;
    BPF_READ(uservaddr_ptr, &v6);

// Copying the IPv6 address
#pragma unroll
    for (int i = 0; i < 16; i++) {
      ed->v6_addr.s6_addr[i] = v6.sin6_addr.in6_u.u6_addr8[i];
    }

    // Reading the IPv6 port
    ed->port =
        my_ntohs(v6.sin6_port); // Convert from network to host byte order
  } break;
  case AF_UNIX:
    BPF_READ(uservaddr_ptr, &ed->unix_addr);
    break;
  }
  // pushes the information to ringbuf connect_event_map map
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};

// exit
SEC("kretprobe/__x64_sys_connect")
int kretprobe_connect_exit(struct pt_regs *ctx) {
  struct event_data *ed;

  // allocate space for an connect_event_map in map.
  ed = BPF_RINGBUF_RESERVE(connect_event_map, *ed);
  if (!ed) {
    return -1;
  }

  ed->id = 1;

  // sets the context
  init_context(&ed->eventContext);

  // return value - int
  ed->ret = (int)PT_REGS_RC_CORE(ctx);

  // pushes the information to ringbuf connect_event_map map
  BPF_RINGBUF_SUBMIT(ed);

  return 0;
};
