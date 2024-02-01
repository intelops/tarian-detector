#ifndef __UTLIS_FILTERS_H__
#define __UTLIS_FILTERS_H__

#include "index.h"

stain bool hasPpid(uint32_t  ppid) { 
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    uint32_t c_ppid = BPF_CORE_READ(task, parent, pid);

    return (c_ppid == ppid); 
}

#endif
