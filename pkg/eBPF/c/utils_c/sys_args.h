#ifndef __UTILS_C_SYS_ARGS_H__
#define __UTILS_C_SYS_ARGS_H__

#include "index.h"

static __always_inline int read_sys_args_into(sys_args_t *dst,
                                              struct pt_regs *src) {

  struct pt_regs *ctx2 = (struct pt_regs *)PT_REGS_PARM1_CORE(src);
  (*dst)[0] = PT_REGS_PARM1_CORE(ctx2);
  (*dst)[1] = PT_REGS_PARM2_CORE(ctx2);
  (*dst)[2] = PT_REGS_PARM3_CORE(ctx2);
  (*dst)[3] = PT_REGS_PARM4_CORE(ctx2);
  (*dst)[4] = PT_REGS_PARM5_CORE(ctx2);

  return 0;
}

#endif