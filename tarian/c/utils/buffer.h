#ifndef __UTLIS_BUFFER_H
#define __UTLIS_BUFFER_H

#include "index.h"

stain int save_to_buffer(program_data_t *, void *, u8, u8);
stain int save_str(syscall_buffer_t *, u32 *, void *, u8, u8);
stain int save_number(syscall_buffer_t *, u32 *, void *, u8, u8, u8);
stain int save_any();
stain int save_str_arr(syscall_buffer_t *, int *, const char *const *, u8, u8);

stain int save_to_buffer(program_data_t *pd, void *src, u8 type, u8 index) {
  switch (type) {
  case UINT_T:
  case INT_T: {
    save_number(&pd->event->buf, &pd->cursor, src, type, index, sizeof(int));
    break;
  }
  case ULONG_T:
  case LONG_T: {
    save_number(&pd->event->buf, &pd->cursor, src, type, index, sizeof(long));
    break;
  }
  case STR_T: {
    save_str(&pd->event->buf, &pd->cursor, src, type, index);
    break;
  }
  case STR_ARR_T: {
    // save_str_arr(&pd->event->buf, (int *)&pd->cursor, (const char *const *)src, type, index);
    break;
  }
  }
  return OK;
}

stain int save_str(syscall_buffer_t *sb, u32 *cursor, void *src, u8 type, u8 index) {
  /*
      Data save format: [index 1B][type 1B][len 2B][.....string.....]
  */

  barrier();
  if (*cursor > (SYS_BUF_SIZE - 1))
    return BUFFER_FULL_ERR;

  // check buffer capacity
  if (*cursor > SYS_BUF_SIZE - (MAX_STRING_SIZE + 4))
    return BUFFER_DATA_SIZE_EXCEEDED_ERR;

  int sz = bpf_probe_read_str(&(sb->data[((int)(*cursor) + 4) & (SYS_BUF_SIZE - 1)]), MAX_STRING_SIZE, src);
  if (sz > 0) {
    barrier();

    if (*cursor > SYS_BUF_SIZE - (MAX_STRING_SIZE + 4))
      return BUFFER_DATA_SIZE_EXCEEDED_ERR;

    bpf_probe_read(&(sb->data[(int)(*cursor) & (SYS_BUF_SIZE - 1)]), 1, &index);
    bpf_probe_read(&(sb->data[((int)(*cursor) + 1) & (SYS_BUF_SIZE - 1)]), 1, &type);
    bpf_probe_read(&(sb->data[((int)(*cursor) + 2) & (SYS_BUF_SIZE - 1)]), 2, &sz);

    *cursor += sz + 4;
    sb->num_fields++;
    return OK;
  }

  return NOT_OK;
}

stain int save_number(syscall_buffer_t *sb, u32 *cursor, void *src, u8 type, u8 index, u8 size) {
  /*
      Data save format: [index 1B][type 1B][...data...sizeB]
  */

  if (size == 0)
    return ZERO_SIZE_ERR;

  barrier();
  if (*cursor > (SYS_BUF_SIZE - 1))
    return BUFFER_FULL_ERR;

  if (*cursor > (SYS_BUF_SIZE - (size + 1)))
    return BUFFER_DATA_SIZE_EXCEEDED_ERR;

  if (bpf_probe_read(&(sb->data[((int)(*cursor) + 2) & (SYS_BUF_SIZE - 1)]), size, src) == 0) {
    bpf_probe_read(&(sb->data[((int)(*cursor)) & (SYS_BUF_SIZE - 1)]), 1, &index);
    bpf_probe_read(&(sb->data[((int)(*cursor) + 1) & (SYS_BUF_SIZE - 1)]), 1, &type);

    *cursor += size + 2;
    sb->num_fields++;

    return OK;
  }

  return NOT_OK;
};

stain int save_str_arr(syscall_buffer_t *sb, int *cursor, const char *const *src, u8 type, u8 index) {
  /*
    Data save format: [index 1B][type 1B][string count 1B][str1 size 2B][str1][str2 size][str2].....
  */

  u8 elem_count = 0;

  if (*cursor > SYS_BUF_SIZE - 1)
    return BUFFER_FULL_ERR;

  u32 orig_off = *cursor;
  *cursor += 3;

  int sz = 0;

#pragma unroll
  for(int i = 0; i < MAX_STR_ARR_ELEM; i++){
    const char *argp = NULL;
    
    bpf_probe_read(&argp, sizeof(argp), &src[i]);
    if (!argp)
      goto exit;

    if (*cursor > SYS_BUF_SIZE - MAX_STRING_SIZE - sizeof(u16))
      goto exit;

    sz = bpf_probe_read_str(&(sb->data[((*cursor + sizeof(u16)) & (SYS_BUF_SIZE - 1))]), MAX_STRING_SIZE, argp);
    if (sz > 0) {
      barrier();

      if (*cursor > SYS_BUF_SIZE - MAX_STRING_SIZE - sizeof(u16))
        goto exit;

      bpf_probe_read(&(sb->data[(*cursor & (SYS_BUF_SIZE - 1))]), sizeof(u16), &sz);
      if (sz < 0 || sz > 10000) {
        goto exit;
      }
      *cursor += sz + sizeof(u16);
      elem_count++;
      continue;
    } else {
      goto exit;
    }
  }

  exit: 
    if (orig_off  > SYS_BUF_SIZE - 3)
      return BUFFER_DATA_SIZE_EXCEEDED_ERR;
    
    if (elem_count != 0){
      sb->data[orig_off] = index;
      sb->data[orig_off + 1] = type;
      sb->data[orig_off + 2] = elem_count;
      sb->num_fields++;
    }
    return OK;
}

// stain int save_str_arr(syscall_buffer_t *sb, u32 *cursor, const char *const *src, u8 type, u8 index) {
//   /*
//       Data save format: [index 1B][type 1B][string count 1B][str1 size
//      2B][str1][str2 size][str2].....
//   */

//   u8 elem_count = 0;

//   if (*cursor > (SYS_BUF_SIZE - 1))
//     return BUFFER_FULL_ERR;

//   int start_cursor = (int)*cursor;
//   *cursor += 3; // /* index */ + 1 /* type */ + 1 /* string count */;

//   for (int i = 0; i < MAX_STR_ARR_ELEM; i++) {
//     const char *arg = NULL;
//     bpf_probe_read(&arg, sizeof(arg), &src[i]);
//     if (!arg)
//       goto exit;
    
//     char temp[128];
//     bpf_probe_read_str(&temp, 128, arg);
//     bpf_printk("test: %d %s", i, temp);
//     if (*cursor > (SYS_BUF_SIZE - MAX_STRING_SIZE - sizeof(u16)))
//       goto exit;

//     int sz = bpf_probe_read_str(&(sb->data[(((int)(*cursor)) + 2)]), MAX_STRING_SIZE, arg);
//     if (sz > 0) {
//       if (*cursor > SYS_BUF_SIZE - MAX_STRING_SIZE - sizeof(u16))
//         goto exit;

//       bpf_probe_read(&(sb->data[(int)(*cursor)]), sizeof(u16), &sz);
//       // *cursor += (u32)sz + 2;
//       // elem_count++;
//       // continue;
//     // } else {
//     //   goto exit;
//     }
//   }

//   char ellipsis[] = "...";
//   if (*cursor > SYS_BUF_SIZE - MAX_STRING_SIZE - 2)
//     goto exit;

//   int sz = bpf_probe_read_str(&(sb->data[((int)(*cursor)) & (SYS_BUF_SIZE - 1)]), MAX_STRING_SIZE, ellipsis);
//   if (sz > 0) {
//     if (*cursor > SYS_BUF_SIZE - 2)
//       goto exit;

//     // bpf_probe_read(&(sb->data[((int)(*cursor)) & (SYS_BUF_SIZE - 1)]), sizeof(u16), &sz);
//     *cursor += sz + sizeof(u16);
//     elem_count++;
//   }

// exit:
//   if (start_cursor > (SYS_BUF_SIZE - 1))
//     return BUFFER_DATA_SIZE_EXCEEDED_ERR;

//   sb->data[start_cursor] = index;
//   sb->data[start_cursor + 1] = type;
//   sb->data[start_cursor + 2] = elem_count;
//   return OK;
// }

#endif