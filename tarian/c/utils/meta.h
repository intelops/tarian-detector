#ifndef UTILS_META_H
#define UTILS_META_H

#include "index.h"

stain int new_event(void *, int, tarian_event_t *, enum allocation_type,int);
stain int init_tarian_meta_data_t(tarian_event_t *, int);
stain int init_task_meta_data_t(tarian_event_t *);
stain int init_event_meta_data_t(tarian_event_t *, int);
stain int read_node_info_into(node_meta_data_t *ni, struct task_struct *t);

stain int new_event(void *ctx, int tarian_event, tarian_event_t *te, enum allocation_type at,int req_buf_sz) {
  stats__add_trigger();

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
  
  if (len > 255) {
    stats__add_buffer();
  }

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

#endif