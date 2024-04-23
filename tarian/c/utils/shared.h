// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

#ifndef __UTILS_SHARED_H__
#define __UTILS_SHARED_H__

#include "index.h"

// License Declaration
char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define KPROBE(__hook) SEC("kprobe/" #__hook)
#define KRETPROBE(__hook) SEC("kprobe/" #__hook)

#if defined(bpf_target_x86)
#define __PT_PARM6_REG r9
#define __PT_SYSCALL_ID orig_ax
#elif defined(bpf_target_arm64)
#define __PT_PARM6_REG regs[5]
#define __PT_SYSCALL_ID syscallno
#endif

#define PT_REGS_PARM6_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), __PT_PARM6_REG)
#define PT_REGS_PARM6_CORE_SYSCALL(x) PT_REGS_PARM6_CORE(x)
#define PT_REGS_SYSCALL_CORE(x)                                                \
  BPF_CORE_READ(__PT_REGS_CAST(x), __PT_SYSCALL_ID)

stain uint32_t get_syscall_id(struct pt_regs *regs) {
  return (uint32_t)PT_REGS_SYSCALL_CORE(regs);
};

stain unsigned long get_syscall_param(struct pt_regs *regs, int idx) {
  unsigned long param = 0;

  if (idx == 0)
    param = PT_REGS_PARM1_CORE_SYSCALL(regs);
  else if (idx == 1)
    param = PT_REGS_PARM2_CORE_SYSCALL(regs);
  else if (idx == 2)
    param = PT_REGS_PARM3_CORE_SYSCALL(regs);
  else if (idx == 3)
    param = PT_REGS_PARM4_CORE_SYSCALL(regs);
  else if (idx == 4)
    param = PT_REGS_PARM5_CORE_SYSCALL(regs);
  else if (idx == 5)
    param = PT_REGS_PARM6_CORE_SYSCALL(regs);

  return param;
}

stain struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}

stain int flush(u8 *buf, u16 n) {
  if (!buf)
    return TDCE_NULL_POINTER;

  u8 zero = 0;

  for (int i = 0; i < n; i++) {
    if (bpf_probe_read(&buf[i], sizeof(u8), &zero) != 0)
      return TDC_FAILURE;
  }
  return TDC_SUCCESS;
}

stain u64 execId(u32 processId, u64 start_time) {
  u64 unique_id = processId;
  unique_id = (unique_id << 32) | start_time;

  return unique_id;
}

stain u64 getExecId(u32 processId, struct task_struct *task) {
  u64 start_time = get_task_start_time(task);
  return execId(processId, start_time);
}

stain u64 getParentExecId(u32 processId, struct task_struct *task) {
  struct task_struct *parent = get_task_parent(task);
  u64 start_time = get_task_start_time(parent);

  return execId(processId, start_time);
}

stain void print_event(tarian_event_t *te) {
  bpf_printk("1. ts %ld 2. event %d 3. syscall %d", te->tarian->meta_data.ts, te->tarian->meta_data.event, te->tarian->meta_data.syscall);
  bpf_printk("4. processor %d 5. starttime %ld 6. comm %s", te->tarian->meta_data.processor, te->tarian->meta_data.task.start_time, te->tarian->meta_data.task.comm);
  bpf_printk("7. hpid %d 8. htgid %d 9. hppid %d", te->tarian->meta_data.task.host_pid, te->tarian->meta_data.task.host_tgid, te->tarian->meta_data.task.host_ppid);
  bpf_printk("10. pid %d 11. tgid %d 12. ppid %d", te->tarian->meta_data.task.pid, te->tarian->meta_data.task.tgid, te->tarian->meta_data.task.ppid);
  bpf_printk("13. uid %d 14. gid %d 15. cgroup %ld", te->tarian->meta_data.task.uid, te->tarian->meta_data.task.gid, te->tarian->meta_data.task.cgroup_id);
  bpf_printk("16. mount %ld 17. pid_ns %ld 18. exec %ld", te->tarian->meta_data.task.mount_ns_id, te->tarian->meta_data.task.pid_ns_id, te->tarian->meta_data.task.exec_id);
  bpf_printk("19. parent_exec %ld 20. sysname %s 21. nodename %s ", te->tarian->meta_data.task.parent_exec_id, te->tarian->system_info.sysname, te->tarian->system_info.nodename);
  bpf_printk("22. release %s 23. version %s", te->tarian->system_info.release, te->tarian->system_info.version);
  bpf_printk("24. machine %s 25. domainname %s 26. nparams %d", te->tarian->system_info.machine, te->tarian->system_info.domainname, te->tarian->meta_data.nparams);
};

stain uint8_t *get__d_path(uint32_t *slen, scratch_space_t *s, struct path *p) {
  struct path path = *p;
  struct dentry *dentry = path.dentry;
  struct vfsmount *vfsmnt = path.mnt;

  struct mount *mnt_p = real_mount(vfsmnt);

  struct mount *mnt_parent_p = NULL;
  bpf_probe_read_kernel(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);

  struct dentry *mnt_root_p = NULL;
  bpf_probe_read_kernel(&mnt_root_p, sizeof(struct dentry *), &vfsmnt->mnt_root);

  uint32_t max_buf_len = MAX_STRING_SIZE;

  struct dentry *d_parent = NULL;
  struct qstr d_name = {};
  s->pos = 0;
  int total_len = 0;
  int effective_name_len = 0;
  char slash = '/';
  char terminator = '\0';

#pragma unroll
  for (int i = 0; i < MAX_NUM_COMPONENTS; i++) {
    bpf_probe_read_kernel(&d_parent, sizeof(struct dentry *), &dentry->d_parent);
    if (dentry == d_parent && dentry != mnt_root_p)
      break;

    if (dentry == mnt_root_p) {
      if (mnt_p != mnt_parent_p) {
        bpf_probe_read_kernel(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
        bpf_probe_read_kernel(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
        bpf_probe_read_kernel(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
        vfsmnt = &mnt_p->mnt;
        bpf_probe_read_kernel(&mnt_root_p, sizeof(struct dentry *), &vfsmnt->mnt_root);
        continue;
      } else
        break;
    }

    bpf_probe_read_kernel(&d_name, sizeof(struct qstr), &dentry->d_name);

    total_len += SAFE_STRING_LEN(d_name.len + 1);

    if (total_len >= MAX_STRING_SIZE) break;
    
    s->pos = max_buf_len - (d_name.len + 1);
    effective_name_len = bpf_probe_read_kernel_str(&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)], SAFE_STRING_LEN(MAX_STRING_SIZE - total_len), (void *)d_name.name);
    if (effective_name_len <= 1)
      break;

    max_buf_len -= 1;
    bpf_probe_read_kernel(&(s->data[SAFE_ACCESS_SCRATCH_SPACE(max_buf_len)]), 1, &slash);
    max_buf_len -= (effective_name_len - 1);

    dentry = d_parent;
  }

  if (max_buf_len == MAX_STRING_SIZE) {
    bpf_probe_read_kernel(&d_name, sizeof(struct qstr), &(dentry->d_name));
    uint64_t sl = bpf_probe_read_kernel_str(&(s->data[0]), MAX_STRING_SIZE, (void *)d_name.name);
    total_len += sl;

    *slen = total_len;
    return s->data;
  }

  max_buf_len -= 1;
  total_len += 1;
  bpf_probe_read_kernel(&(s->data[SAFE_ACCESS_SCRATCH_SPACE(max_buf_len)]), 1, &slash);

  bpf_probe_read_kernel(&(s->data[SAFE_ACCESS_SCRATCH_SPACE(MAX_SCRATCH_SPACE_SIZE - 1)]), 1, &terminator);

  *slen = total_len;
  return &(s->data[SAFE_ACCESS_SCRATCH_SPACE(max_buf_len)]);
}

/**
 * n - start index of char array
*/
stain uint8_t *read_char_arr(uint32_t *rlen, scratch_space_t *s, char **char_arr, uint16_t n) {
  u8 space = 32, zero = 0;
  unsigned long charbuf_pointer = 0;
  uint16_t arg_len = 0;
  uint16_t total_len = 0;
  s->pos = 0;

#pragma unroll
  for (; n < MAX_CHARBUF_POINTERS; ++n) {
    bpf_probe_read_user(&charbuf_pointer, sizeof(charbuf_pointer), &char_arr[n]);
    if (!charbuf_pointer)
      break;
    
    /* Replace null('\0') character with space(' ') */
    if (total_len != 0) {
      s->pos--;
      
      *((uint8_t *)&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)]) = space;
      s->pos += sizeof(uint8_t);      
    }

    arg_len = bpf_probe_read_user_str(&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)], MAX_STRING_SIZE, (char *)charbuf_pointer);
    if (arg_len <= 0) {
      break;
    }
    
    // Wrong logic recheck this if element is of length 4096
    if (total_len + arg_len >= MAX_STRING_SIZE) {
      s->pos--;

      *((uint8_t *)&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)]) = zero;
      s->pos += sizeof(uint8_t);

      break;
    };

    total_len += arg_len;
    s->pos += SAFE_STRING_LEN(arg_len);
  }

  *rlen = total_len;
  return &(s->data[0]);
}

stain uint8_t *read_iovec_arr(uint32_t *rlen, scratch_space_t *s, unsigned long iovec_ptr, unsigned long iov_count){
  uint32_t total_len = 0;
  s->pos = 0;
  *rlen = 0;

  uint32_t total_iovec_size = iov_count * bpf_core_type_size(struct iovec);
  if (bpf_probe_read_user((void *)&s->data[HALF_SCRATCH_SPACE_SIZE], SAFE_ACCESS_SCRATCH_SPACE(total_iovec_size), (void *)iovec_ptr) != 0)
    return NULL;
  
  const struct iovec *iovecs = (const struct iovec *)&s->data[HALF_SCRATCH_SPACE_SIZE];
  for (int i = 0; i < MAX_IOVEC_COUNT; i++) {
    if (i == (SAFE_IOVEC_COUNT(iov_count)))
      break;

    int16_t bytes_read = bpf_probe_read_user(&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)], (iovecs[i].iov_len >= MAX_STRING_SIZE? MAX_STRING_SIZE: SAFE_STRING_LEN(iovecs[i].iov_len)), iovecs[i].iov_base);
    if (bytes_read != 0)
      break;
    
    if (iovecs[i].iov_len == MAX_STRING_SIZE) {
      total_len += MAX_STRING_SIZE;
      s->pos += MAX_STRING_SIZE;
    } else {
      total_len += SAFE_STRING_LEN(iovecs[i].iov_len);
      s->pos += SAFE_ACCESS_SCRATCH_SPACE(iovecs[i].iov_len);
    }

    if (total_len >= MAX_STRING_SIZE) break;
  }

  *rlen = total_len;
  return &(s->data[0]);
}

stain uint8_t *read_sockaddr(uint32_t *rlen, scratch_space_t *s, unsigned long data_ptr, uint16_t addrlen) {
  uint32_t total_len = 0;
  s->pos = 0;
  *rlen = 0;

  if (bpf_probe_read((void *)&s->data[HALF_SCRATCH_SPACE_SIZE], SAFE_ACCESS_SCRATCH_SPACE(addrlen), (void *)data_ptr) != 0)
    return NULL;

  struct sockaddr *sockaddr = (struct sockaddr *)&s->data[HALF_SCRATCH_SPACE_SIZE];
  uint16_t socket_family = sockaddr->sa_family;

  *((uint16_t *)&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)]) = socket_family;
  s->pos += sizeof(uint16_t);
  total_len += sizeof(uint16_t);

  switch(socket_family) {
  case AF_INET: {
    struct sockaddr_in *sin = (struct sockaddr_in*)sockaddr;

    uint32_t ipv4 = sin->sin_addr.s_addr;
    uint16_t port = sin->sin_port;

    *((uint32_t *)&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)]) = ipv4;
    s->pos += sizeof(uint32_t);

    *((uint16_t *)&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)]) = port;
    s->pos += sizeof(uint16_t);
    
    total_len += 6;
    break;
  }
  case AF_INET6: {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sockaddr;
    
    uint16_t port = sin6->sin6_port;

    __builtin_memcpy(&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)], sin6->sin6_addr.in6_u.u6_addr32, 16);
    s->pos += 16;

    *((uint16_t *)&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)]) = port;
    s->pos += sizeof(uint16_t);

    total_len += 18;
    break;
  }
  case AF_UNIX: {
    struct sockaddr_un *sunix = (struct sockaddr_un*)sockaddr;

    unsigned long start_reading_point;
    char first_path_byte = *(char *)sunix->sun_path;
    if  (first_path_byte == '\0')
      start_reading_point = (unsigned long)sunix->sun_path + 1;
    else 
      start_reading_point = (unsigned long)sunix->sun_path;

    
    uint32_t sp_len = bpf_probe_read_kernel_str(&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos+2)], MAX_UNIX_SOCKET_PATH, (char *)start_reading_point);
    
    *((uint16_t *)&s->data[SAFE_ACCESS_SCRATCH_SPACE(s->pos)]) = sp_len;
    s->pos += sizeof(uint16_t);
    
    total_len += sp_len + 2;
    break;    
  }
  }

  *rlen = total_len;
  return &(s->data[0]);
}

#endif