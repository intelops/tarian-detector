#ifndef __UTILS_SHARED_H__
#define __UTILS_SHARED_H__

#include "index.h"

long total = 0, dropped = 0;
// License Declaration
char LICENSE[] SEC("license") = "Dual MIT/GPL";

#if defined(bpf_target_x86)
#define PT_REGS_PARM6_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM6_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), regs[5])
#endif

#if defined(bpf_target_x86)
#define PT_REGS_SYSCALL_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), orig_ax)
#elif defined(bpf_target_arm64)
#define PT_REGS_SYSCALL_CORE(x) BPF_CORE_READ(__PT_REGS_CAST(x), syscallno)
#endif

// bpf_probe_read_str
#define BPF_READ_STR(__from_ptr__, __to_ptr__)                                 \
  bpf_probe_read_str(__to_ptr__, sizeof(typeof(*__to_ptr__)), __from_ptr__)

// bpf_probe_read
#define BPF_READ(__from_ptr__, __to_ptr__)                                     \
  bpf_probe_read(__to_ptr__, sizeof(typeof(*__to_ptr__)), __from_ptr__)

// bpf_get_comm
#define BPF_GET_COMM(__var__) bpf_get_current_comm(&__var__, sizeof(__var__))

// read array of strings
stain int read_str_arr_to_ptr(const char *const *from, u8 (*to)[MAX_STRING_SIZE]) {
  if (to == NULL || from == NULL)
    return -1;

  int i = 0;
  u8 *curr_ptr;

  while (i < 20) {
    BPF_READ(&from[i], &curr_ptr);
    if (curr_ptr == NULL) {
      break;
    }

    BPF_READ_STR(curr_ptr, &to[i]);
    i++;
  };

  return 0;
};

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

stain struct ringbuffer *get_cpu_ringbuffer()
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)  
	uint32_t cpu_id = (uint32_t)bpf_get_smp_processor_id();
	return (struct ringbuffer *)bpf_map_lookup_elem(&events, &cpu_id);
#else
  return NULL;
#endif
}

stain void *events_reserve_space(int size) {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)  
  struct ringbuffer *rb = get_cpu_ringbuffer();
  if (!rb) {
    // bpf_printk("Failed to reserve space in per-CPU ring buffer\n %ld %ld", total, mapp);
    return NULL;
  }

  // bpf_printk("reserve space in per-CPU ring buffer\n %ld %ld", total, mapp);
  return bpf_ringbuf_reserve(rb, size, 0);
#else

  int zero = 0;

  return bpf_map_lookup_elem(&pea_per_cpu_array, &zero);
#endif
}

stain int events_ringbuf_submit(program_data_t *ptr) {
  if (ptr == NULL)
    return NULL_POINTER_ERROR;
  
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  BPF_RINGBUF_SUBMIT(ptr->event);
#else
  bpf_perf_event_output(ptr->ctx, &events, BPF_F_CURRENT_CPU, ptr->event, sizeof(*ptr->event));
#endif

  // bpf_printk("test: Total triggers: %ld, total drops: %ld", total, dropped);  
  // bpf_printk("execve %d %d", ptr->event->context.task.host_pid , ptr->event->buf.num_fields);
  // bpf_printk("Execve %ld %ld %d", sizeof(*ptr->event), sizeof(ptr->event), rl);

  return OK;
}

stain int events_ringbuf_discard(program_data_t *ptr){
  if (ptr == NULL)
      return NULL_POINTER_ERROR;
  
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
  BPF_RINGBUF_DISCARD(ptr->event);
#endif

  return OK;
}

stain int flush(u8 *buf, int n) {
  if (buf == NULL) 
    return NULL_POINTER_ERROR;

  u8 zero = 0;

  for (int i = 0; i < n; i++){
    bpf_probe_read(&buf[i], sizeof(u8), &zero);
  }
  return OK;
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


#endif