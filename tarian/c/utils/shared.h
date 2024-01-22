#ifndef __UTILS_SHARED_H__
#define __UTILS_SHARED_H__

#include "index.h"

long total = 0, dropped = 0;

// License Declaration
char LICENSE[] SEC("license") = "Dual MIT/GPL";

#define KPROBE(__hook) SEC("kprobe/"#__hook)
#define KRETPROBE(__hook) SEC("kprobe/"#__hook)

// #define SAFE_ACCESS(x) x &(MAX_PARAM_SIZE)

/* Given a variable, this returns its `char` pointer. */
#define CHAR_POINTER(x) (char *)&x

#if defined(bpf_target_x86)
#define __PT_PARM6_REG r9
#define __PT_SYSCALL_ID orig_ax
#elif defined(bpf_target_arm64)
#define __PT_PARM6_REG regs[5]
#define __PT_SYSCALL_ID syscallno
#endif

#define PT_REGS_PARM6_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), __PT_PARM6_REG)
#define PT_REGS_PARM6_CORE_SYSCALL(x) PT_REGS_PARM6_CORE(x)
#define PT_REGS_SYSCALL_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), __PT_SYSCALL_ID)

stain uint32_t get_syscall_id(struct pt_regs *regs) {
  return (uint32_t)PT_REGS_SYSCALL_CORE(regs);
};

stain unsigned long get_syscall_param(struct pt_regs *regs, int idx) {
  switch (idx)
  {
  case 0:
    return PT_REGS_PARM1_CORE_SYSCALL(regs);
  case 1:
    return PT_REGS_PARM2_CORE_SYSCALL(regs);
  case 2:
    return PT_REGS_PARM3_CORE_SYSCALL(regs);
  case 3:
    return PT_REGS_PARM4_CORE_SYSCALL(regs);
  case 4: 
    return PT_REGS_PARM5_CORE_SYSCALL(regs);
  case 5:
    return PT_REGS_PARM6_CORE_SYSCALL(regs);
  default:
    return TDCE_UNDEFINED_INDEX;
  }
}

// #if defined(bpf_target_x86)
// #define PT_REGS_PARM6_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), r9)
// #elif defined(bpf_target_arm64)
// #define PT_REGS_PARM6_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), regs[5])
// #endif

// bpf_probe_read_str
#define BPF_READ_STR(__from_ptr__, __to_ptr__)                                 \
  bpf_probe_read_str(__to_ptr__, sizeof(typeof(*__to_ptr__)), __from_ptr__)

// bpf_probe_read
#define BPF_READ(__from_ptr__, __to_ptr__)                                     \
  bpf_probe_read(__to_ptr__, sizeof(typeof(*__to_ptr__)), __from_ptr__)

// bpf_get_comm
#define BPF_GET_COMM(__var__) bpf_get_current_comm(&__var__, sizeof(__var__))

stain bool shouldContinue(char *target, int size){
  char src[16];
  bpf_get_current_comm(&src, 16);

  for (int i = 0; i < size; i++){
    if(target[i] != src[i])
      return false;
  }

  return true;
}

// read array of strings
// stain int read_str_arr_to_ptr(const char *const *from, u8 (*to)[MAX_STRING_SIZE]) {
//   if (to == NULL || from == NULL)
//     return -1;

//   int i = 0;
//   u8 *curr_ptr;

//   while (i < 20) {
//     BPF_READ(&from[i], &curr_ptr);
//     if (curr_ptr == NULL) {
//       break;
//     }

//     BPF_READ_STR(curr_ptr, &to[i]);
//     i++;
//   };

//   return 0;
// };

// reads user id and group id to the pointers
stain int get_uid_gid(void *ptr_uid, void *ptr_gid) {
  if (ptr_uid == NULL || ptr_gid == NULL)
    return -1;

  u64 uid_gid = bpf_get_current_uid_gid();
  *(u32 *)ptr_uid = uid_gid >> 32;
  *(u32 *)ptr_gid = uid_gid;

  return 0;
}

// reads cwd to the pointer
stain int get_cwd(u8 (*to_ptr_arr)[32]) {
  if (to_ptr_arr == NULL)
    return -1;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct fs_struct *fs;
  struct dentry *dentry;

  fs = BPF_CORE_READ(task, fs);
  if (fs == NULL)
    return -1;

  dentry = BPF_CORE_READ(fs, pwd.dentry);
  if (dentry == NULL)
    return -1;

  return BPF_READ_STR(&dentry->d_iname, to_ptr_arr);
}

stain struct mount *real_mount(struct vfsmount *mnt) {
  return container_of(mnt, struct mount, mnt);
}

stain struct dentry *get_mnt_root_ptr(struct vfsmount *vfsmnt){
  return BPF_CORE_READ(vfsmnt, mnt_root);
}

stain struct dentry *get_d_parent_ptr(struct dentry *dentry){
  return BPF_CORE_READ(dentry, d_parent);
}

stain struct qstr get_d_name_from_dentry(struct dentry *dentry){
  return BPF_CORE_READ(dentry, d_name);
}

stain int flush(u8 *buf, u16 n) {
  if (!buf) 
    return TDCE_NULL_POINTER;

  u8 zero = 0;

  for (int i = 0; i < n; i++){
    if(bpf_probe_read(&buf[i], sizeof(u8), &zero) != 0) return TDC_FAILURE;    
  }
  return TDC_SUCCESS;
}

stain u64 execId(u32 processId, u64 start_time){
    u64 unique_id = processId;
    unique_id = (unique_id << 32) | start_time;

    // for (int i = 0; i < (command_size & (TASK_COMM_LEN - 1)); i++) {
    //     if (command[i] == '\0') 
    //       break;

    //     unique_id = (unique_id << 8) | (u8)command[i & (TASK_COMM_LEN - 1)];
    // }

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
  bpf_printk("Execve 1. ts %ld 2. event %d 3. syscall %d", te->tarian->meta_data.ts, te->tarian->meta_data.event, te->tarian->meta_data.syscall);
  bpf_printk("Execve 4. processor %d 5. starttime %ld 6. comm %s", te->tarian->meta_data.processor, te->tarian->meta_data.task.start_time, te->tarian->meta_data.task.comm);
  bpf_printk("Execve 7. hpid %d 8. htgid %d 9. hppid %d", te->tarian->meta_data.task.host_pid, te->tarian->meta_data.task.host_tgid, te->tarian->meta_data.task.host_ppid);
  bpf_printk("Execve 10. pid %d 11. tgid %d 12. ppid %d", te->tarian->meta_data.task.pid, te->tarian->meta_data.task.tgid, te->tarian->meta_data.task.ppid);
  bpf_printk("Execve 13. uid %d 14. gid %d 15. cgroup %ld", te->tarian->meta_data.task.uid, te->tarian->meta_data.task.gid, te->tarian->meta_data.task.cgroup_id);
  bpf_printk("Execve 16. mount %ld 17. pid_ns %ld 18. exec %ld", te->tarian->meta_data.task.mount_ns_id, te->tarian->meta_data.task.pid_ns_id, te->tarian->meta_data.task.exec_id);
  bpf_printk("Execve 19. parent_exec %ld 20. sysname %s 21. nodename %s ", te->tarian->meta_data.task.parent_exec_id, te->tarian->system_info.sysname, te->tarian->system_info.nodename);
  bpf_printk("Execve 22. release %s 23. version %s", te->tarian->system_info.release, te->tarian->system_info.version);
  bpf_printk("Execve 24. machine %s 25. domainname %s", te->tarian->system_info.machine, te->tarian->system_info.domainname);
};

#endif