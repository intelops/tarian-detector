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
  bpf_printk("27. cwd %s", te->tarian->meta_data.task.cwd);
};

#define SCRATCH_SAFE_ACCESS(x) (x) & (MAX_STRING_SIZE - 1)
stain uint8_t *get__cwd_d_path(uint32_t *slen, scratch_space_t *s, struct task_struct *task) {
  struct path path = BPF_CORE_READ(task, fs, pwd);
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
  int len = 0;
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

    len += (d_name.len + 1) & (MAX_STRING_SIZE - 1);

    s->pos = max_buf_len - (d_name.len + 1);
    effective_name_len = bpf_probe_read_kernel_str(&s->data[SCRATCH_SAFE_ACCESS(s->pos)], MAX_STRING_SIZE, (void *)d_name.name);
    if (effective_name_len <= 1)
      break;

    max_buf_len -= 1;
    bpf_probe_read_kernel(&(s->data[SCRATCH_SAFE_ACCESS(max_buf_len)]), 1, &slash);
    max_buf_len -= (effective_name_len - 1);

    dentry = d_parent;
  }

  if (max_buf_len == MAX_STRING_SIZE) {
    bpf_probe_read_kernel(&d_name, sizeof(struct qstr), &(dentry->d_name));
    uint64_t sl = bpf_probe_read_kernel_str(&(s->data[0]), MAX_STRING_SIZE, (void *)d_name.name);
    len += sl;

    *slen = len;
    return s->data;
  }

  max_buf_len -= 1;
  len += 1;
  bpf_probe_read_kernel(&(s->data[SCRATCH_SAFE_ACCESS(max_buf_len)]), 1, &slash);

  bpf_probe_read_kernel(&(s->data[SCRATCH_SAFE_ACCESS(MAX_SCRATCH_SPACE - 1)]), 1, &terminator);

  *slen = len;
  return &(s->data[SCRATCH_SAFE_ACCESS(max_buf_len)]);
}

#endif