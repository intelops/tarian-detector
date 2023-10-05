#ifndef __UTLIS_C_BUFFER_H
#define __UTLIS_C_BUFFER_H

#include "index.h"

stain int save_to_buffer(program_data_t *, void *, u8, u8);
stain int save_str(syscall_buffer_t *, u32 *, void *, u8, u8);
stain int save_int_to_buf();
stain int save_any_to_buf();
stain int save_str_arr_to_buf(syscall_buffer_t *, u32 *, void *, u8, u8);

stain int save_to_buffer(program_data_t *pd, void *src, u8 type, u8 index) {

    save_str(&pd->event->buf, &pd->cursor, src, type, index);
    return OK;
}

stain int save_str(syscall_buffer_t *sb, u32 *cursor, void *src, u8 type, u8 index){
    /*
        Data save format: [index 1B][type 1B][len 2B][.....string.....]
    */

    if (*cursor > (MAX_SYSCALL_BUFFER_SIZE - 1)) 
        return BUFFER_FULL_ERR;

    // check buffer capacity
    if (*cursor > MAX_SYSCALL_BUFFER_SIZE - (MAX_STRING_SIZE + 4))
        return  BUFFER_DATA_SIZE_EXCEEDED_ERR;
    
    int sz = bpf_probe_read_str(&(sb->data[(int)(*cursor) + 4]), MAX_STRING_SIZE, src);
    if (sz > 0) {
        barrier();

        if (*cursor > MAX_SYSCALL_BUFFER_SIZE - (MAX_STRING_SIZE + 4))
            return BUFFER_DATA_SIZE_EXCEEDED_ERR;

        bpf_probe_read(&(sb->data[(int)(*cursor)]), 1, &index);
        bpf_probe_read(&(sb->data[(int)(*cursor) + 1]), 1, &type);
        bpf_probe_read(&(sb->data[((int)(*cursor) + 2)]), 2, &sz);
        
        *cursor += sz + 5; 
        sb->num_fields++;
        return OK;
    }

    return OK;
}

stain int save_str_arr_to_buf(syscall_buffer_t *sb, u32 *cursor, void *src, u8 type, u8 index) {
    /*
        Data save format: [index 1B][string count 2B][str1 size][str1][str2 size][str2].....
    */

    if (*cursor > (MAX_SYSCALL_BUFFER_SIZE - 1)) 
        return BUFFER_FULL_ERR;

    // u32 orig_off = *cursor + 1;
    *cursor += 2;

    
    return OK;
}
#endif