#ifndef __UTILS_C_CONTEXT_H__
#define __UTILS_C_CONTEXT_H__

#include "index.h"

// func definitions
stain int read_cwd_into(struct path *, u8 *);
stain int new_program(program_data_t *pd, void *, int);
stain int read_node_info_into(node_info_t *, struct task_struct *);
stain int init_task_context(task_context_t *, struct task_struct *);
stain int init_event_context(event_context_t *, struct task_struct *, int, int);

stain int new_program(program_data_t *pd, void *ctx, int event_id) {
  pd->ctx = ctx; /* pt regs ctx*/
  pd->task = (struct task_struct *)bpf_get_current_task(); /* task struct pointer*/
  pd->cursor = 0;

  // reads syscall arguments
  int err = read_sys_ctx_into(&pd->sys_ctx, pd->ctx);
  if (err != OK)
    return err;

  pd->event = BPF_RINGBUF_RESERVE(EVENT_RINGBUF_MAP_NAME, *pd->event);
  if (!pd->event)
    return RINGBUF_CAPACITY_REACHED_ERR;

  pd->event->buf.num_fields = 0;
  pd->event->buf.field_types = 0;
  flush(pd->event->buf.data, sizeof(pd->event->buf.data));

  err = init_event_context(&pd->event->context, pd->task, event_id /* event id */, (int)(pd->sys_ctx[6]) /* syscall id */);
  if (err != OK) {
    events_ringbuf_discard(pd);
    return err;
  }

  err = read_node_info_into(&pd->event->system_info, pd->task);
  if (err != OK)
    return err;

  return OK;
};

stain int init_event_context(event_context_t *e, struct task_struct *t, int event_id, int syscall_id) {
  int err = init_task_context(&e->task, t);
  if (err != OK)
    return err;

  e->ts = bpf_ktime_get_ns();
  e->event_id = event_id;
  e->syscall = syscall_id;
  e->processor_id = (u16)bpf_get_smp_processor_id();

  return OK;
}

stain int init_task_context(task_context_t *tc, struct task_struct *t) {
  tc->start_time = get_task_start_time(t);

  u64 tpid = bpf_get_current_pid_tgid();
  tc->host_tgid = tpid;
  tc->host_pid = tpid >> 32;

  tc->host_ppid = get_task_ppid(t);

  tc->pid = get_task_ns_tgid(t);
  tc->tgid = get_task_ns_pid(t);

  tc->ppid = get_task_ns_ppid(t);

  u64 tuid = bpf_get_current_uid_gid();
  tc->gid = tuid >> 32;
  tc->uid = tuid;

  tc->cgroup_id = bpf_get_current_cgroup_id();

  tc->mount_ns_id = get_mnt_ns_id(get_task_nsproxy(t));
  tc->pid_ns_id = get_pid_ns_id(get_task_nsproxy(t));

  flush(tc->comm, sizeof(tc->comm));
  if (BPF_GET_COMM(tc->comm) < 0)
    return NOT_OK;

  struct path path = BPF_CORE_READ(t, fs, pwd);
  flush(tc->cwd, sizeof(tc->cwd));
  return read_cwd_into(&path, tc->cwd);
}

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

  return OK;
};

// task->nsproxy->uts_ns->name
stain int read_node_info_into(node_info_t *ni, struct task_struct *t) {
  if (ni == NULL)
    return NULL_POINTER_ERROR;

  struct uts_namespace *uts_ns = get_uts_ns(get_task_nsproxy(t));
  BPF_CORE_READ_INTO(ni, uts_ns, name);

  return OK;
}

#endif