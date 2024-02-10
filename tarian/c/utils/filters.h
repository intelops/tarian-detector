#ifndef UTLIS_FILTERS_H
#define UTLIS_FILTERS_H

#include "index.h"

stain bool has_same_ppid(uint32_t  ppid) { 
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    uint32_t c_ppid = BPF_CORE_READ(task, parent, pid);

    return (c_ppid == ppid); 
}

stain bool has_same_comm(char *comm, int len) {
    char buf[TASK_COMM_LEN];
    bpf_get_current_comm(&buf, TASK_COMM_LEN);

    for (int i=0;i<TASK_COMM_LEN;i++) {
        if (i == len) break;

        if  (buf[i] != comm[i]) return false;
    }

    return true;
}
#endif
