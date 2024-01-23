#ifndef __UTILS_META_H__
#define __UTILS_META_H__

#include "index.h"

stain int new_event(void *, int, tarian_event_t *, enum allocation_type,int);
stain int init_tarian_meta_data_t(tarian_event_t *, int);
stain int init_task_meta_data_t(tarian_event_t *);
stain int init_event_meta_data_t(tarian_event_t *, int);
stain int read_node_info_into(node_meta_data_t *ni, struct task_struct *t);
stain int read_cwd_into(struct path *, u8 *);

stain int new_event(void *ctx, int tarian_event, tarian_event_t *te, enum allocation_type at,int req_buf_sz) {
  te->allocation_mode = 0;
  te->ctx = ctx;
  te->task = (struct task_struct *)bpf_get_current_task();
  
  scratch_space_t *ss = get__scratch_space();
  if (!ss) return TDCE_SCRATCH_SPACE_ALLOCATION;

  int resp = tdf_reserve_space(te, at , req_buf_sz);
  if (resp != TDC_SUCCESS) return resp;

  resp = flush(te->buf.data, te->buf.reserved_space);
  if (resp != TDC_SUCCESS) {
    tdf_discard_event(te);
    return resp;
  };

  resp = init_tarian_meta_data_t(te, tarian_event);
  if (resp != TDC_SUCCESS) return resp;
  
  uint32_t len = 0;
  u8 *filepath = get__cwd_d_path(&len, ss, te->task);
  
  bpf_probe_read_kernel_str(te->tarian->meta_data.task.cwd, len & (MAX_TARIAN_PATH - 1), filepath);
  
  return TDC_SUCCESS;
};

stain int init_tarian_meta_data_t(tarian_event_t *te, int event) {
  te->tarian = (tarian_meta_data_t *)te->buf.data;
  te->buf.pos = sizeof(tarian_meta_data_t);

  int resp = init_event_meta_data_t(te, event);
  if (resp != TDC_SUCCESS) return resp;

  return read_node_info_into(&te->tarian->system_info, te->task);
};

stain int init_event_meta_data_t(tarian_event_t *te, int event) {
    event_meta_data_t *em = &te->tarian->meta_data;

    em->ts = bpf_ktime_get_ns();
    em->event = event;
    em->nparams = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
    em->syscall = get_syscall_id(te->ctx);
#else
    struct pt_regs *regs = PT_REGS_SYSCALL_REGS(te->ctx);
    em->syscall = get_syscall_id(regs);
#endif
    em->processor = (uint16_t)bpf_get_smp_processor_id();

    return init_task_meta_data_t(te);
};

stain int init_task_meta_data_t(tarian_event_t *te) {
    task_meta_data_t *tm = &te->tarian->meta_data.task;

    tm->start_time = get_task_start_time(te->task);

    u64 ptid = bpf_get_current_pid_tgid();
    tm->host_tgid = ptid;
    tm->host_pid = ptid >> 32;

    tm->host_ppid = get_task_ppid(te->task);

    tm->pid = get_task_ns_tgid(te->task);
    tm->tgid = get_task_ns_pid(te->task);

    tm->ppid = get_task_ns_ppid(te->task);

    u64 guid = bpf_get_current_uid_gid();
    tm->uid = guid;
    tm->gid = guid >> 32;

    tm->cgroup_id = bpf_get_current_cgroup_id();

    tm->mount_ns_id = get_mnt_ns_id(get_task_nsproxy(te->task));
    tm->pid_ns_id = get_pid_ns_id(get_task_nsproxy(te->task));

    tm->exec_id = getExecId(tm->host_pid, te->task);
    tm->parent_exec_id = getParentExecId(tm->host_ppid, te->task);

    bpf_get_current_comm(tm->comm, TASK_COMM_LEN);
    
    return TDC_SUCCESS;
};

stain int read_node_info_into(node_meta_data_t *nm, struct task_struct *t) {
  if (nm == NULL)
    return TDCE_NULL_POINTER;

  struct uts_namespace *uts_ns = get_uts_ns(get_task_nsproxy(t));
  BPF_CORE_READ_INTO(nm, uts_ns, name);

  return TDC_SUCCESS;
};

stain int read_cwd_into(struct path *path, u8 *buf) {
  /*
    Data saved to buf: [start index of string 2byte][size of the string 2byte]....[...string....]
  */
  char slash = '/';
  int zero = 0;
  int sz = 0;

  struct path file_path;
  bpf_probe_read(&file_path, sizeof(struct path), path);

  struct dentry *dentry = file_path.dentry;
  struct vfsmount *vfsmnt = file_path.mnt;

  struct mount *mnt_parent_p;
  struct mount *mnt_p = real_mount(vfsmnt);

  bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);

  struct dentry *mnt_root;
  struct dentry *d_parent;
  struct qstr d_name;

  unsigned int len = 0;
  short cursor = MAX_STRING_SIZE - 1; // current index in buffer. starts with 4095
  short str_len = 0; // total size of string written to buffer

#pragma unroll
  for (int i = 0; i < MAX_PATH_LOOP /* 20 */; i++) {
    mnt_root = get_mnt_root_ptr(vfsmnt);
    d_parent = get_d_parent_ptr(dentry);

    if (dentry == mnt_root || dentry == d_parent) {
      if (dentry != mnt_root) {
        break;
      }
      if (mnt_p != mnt_parent_p) {
        bpf_probe_read(&dentry, sizeof(struct dentry *), &mnt_p->mnt_mountpoint);
        bpf_probe_read(&mnt_p, sizeof(struct mount *), &mnt_p->mnt_parent);
        bpf_probe_read(&mnt_parent_p, sizeof(struct mount *), &mnt_p->mnt_parent);
        vfsmnt = &mnt_p->mnt;

        continue;
      }

      break;
    }

    d_name = get_d_name_from_dentry(dentry);
    len = (d_name.len + 1) & (MAX_STRING_SIZE - 1);

    // Check buffer capacity
    if ((MAX_STRING_SIZE - str_len - sizeof(int) /* for string index and len */ - 1 /* for null byte at the end*/) < MAX_STRING_SIZE) {
      cursor -= len;
      sz = bpf_probe_read_str(&(buf[cursor & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
    } else
      break;

    if (sz > 1) {
      str_len += sz;
      bpf_probe_read(&(buf[(cursor + len - 1) & (MAX_STRING_SIZE - 1)]), 1, &slash);
    } else
      break;

    dentry = d_parent;
  }

  if (cursor == MAX_STRING_SIZE - 1) {
    d_name = get_d_name_from_dentry(dentry);
    len = (d_name.len) & (MAX_STRING_SIZE - 1);
    cursor -= len;
    sz = bpf_probe_read_str(&(buf[cursor & (MAX_STRING_SIZE - 1)]), MAX_STRING_SIZE, (void *)d_name.name);
    str_len += sz;
  } else {
    cursor -= 1;
    bpf_probe_read(&(buf[cursor & (MAX_STRING_SIZE - 1)]), 1, &slash);
    bpf_probe_read(&(buf[MAX_STRING_SIZE - 1]), 1, &zero);
    str_len += 2; /* 1 for null termination + 1 for adding slash in the begning of the string */
  }

  // write start index of string to buffer
  bpf_probe_read(&(buf[0]), sizeof(short), &cursor);
  bpf_probe_read(&(buf[2]), sizeof(short), &str_len);

  // bpf_printk("string: cwd %d, %d", cursor, str_len);

  // u32 ret = ((u32)cursor << 16) | str_len;

  return TDC_SUCCESS;
};

#define MAX_LOOP 16
stain int read_str_arr_to_ptr(const char *const *from_ptr,
                    __u8 *to_ptr, u64 *pos) {
  if (to_ptr == NULL || from_ptr == NULL)
    return -1;

  int i = 0;
  __u8 *curr_ptr;

  while (i < MAX_LOOP) {
    BPF_READ(&from_ptr[i], &curr_ptr);
    if (curr_ptr == NULL) {
      break;
    }

    char arr[28];
    bpf_probe_read_user_str(&arr, 28, curr_ptr);
    // BPF_READ_STR(curr_ptr, &to_ptr[SAFE_ACCESS(*pos)]);
    bpf_printk("Execve ,,,,,,,,,,,%d %s", i, arr);
    *pos += 5;
    i++;
  };

  return 0;
};
#endif