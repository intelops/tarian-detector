#ifndef __UTILS_C_SHARED_H__
#define __UTILS_C_SHARED_H__

#include "index.h"

// License Declaration
char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Ringbuffer map definition
#define BPF_RINGBUF_MAP(__name__)                                              \
  struct {                                                                     \
    __uint(type, BPF_MAP_TYPE_RINGBUF);                                        \
    __uint(max_entries, 1 << 24);                                              \
  } __name__ SEC(".maps");

// Ringbuf helpers
#define BPF_RINGBUF_SUBMIT(__var__) bpf_ringbuf_submit(__var__, 0)
#define BPF_RINGBUF_DISCARD(__var__) bpf_ringbuf_discard(__var__, 0)
#define BPF_RINGBUF_RESERVE(__map_name__, __var__)                             \
  bpf_ringbuf_reserve(&__map_name__, sizeof(__var__), 0)

// bpf_probe_read_str
#define BPF_READ_STR(__from_ptr__, __to_ptr__)                                 \
  bpf_probe_read_str(__to_ptr__, sizeof(typeof(*__to_ptr__)), __from_ptr__);

// bpf_probe_read
#define BPF_READ(__from_ptr__, __to_ptr__)                                     \
  bpf_probe_read(__to_ptr__, sizeof(typeof(*__to_ptr__)), __from_ptr__)

// bpf_get_comm
#define BPF_GET_COMM(__var__) bpf_get_current_comm(&__var__, sizeof(__var__))

// read array of strings
static __always_inline int
read_str_arr_to_ptr(const char *const *from,
                    __u8 (*to)[MAX_STRING_SIZE]) {
  if (to == NULL || from == NULL)
    return -1;

  int i = 0;
  __u8 *curr_ptr;

  while (i < MAX_LOOP) {
    BPF_READ(&from[i], &curr_ptr);
    if (curr_ptr == NULL) {
      break;
    }

    BPF_READ_STR(curr_ptr, &to[i]);
    i++;
  };

  return 0;
};

// reads process id and thread group id to the pointers
static __always_inline int get_pid_tgid(void *ptr_pid, void *ptr_tgid) {
  if (ptr_pid == NULL || ptr_tgid == NULL)
    return -1;

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  *(__u32 *)ptr_pid = pid_tgid >> 32;
  *(__u32 *)ptr_tgid = pid_tgid;

  return 0;
}

// reads user id and group id to the pointers
static __always_inline int get_uid_gid(void *ptr_uid, void *ptr_gid) {
  if (ptr_uid == NULL || ptr_gid == NULL)
    return -1;

  __u64 uid_gid = bpf_get_current_uid_gid();
  *(__u32 *)ptr_uid = uid_gid >> 32;
  *(__u32 *)ptr_gid = uid_gid;

  return 0;
}

// reads cwd to the pointer
static __always_inline int get_cwd(__u8 (*to_ptr_arr)[32]) {
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

#endif