#ifndef __UTILS_SHARED_WRITER_H__
#define __UTILS_SHARED_WRITER_H__

enum memory { KERNEL = 0, USER = 1 };

#define MAX_EVENT_SIZE 64 * 1024
#define MAX_PARAM_SIZE MAX_EVENT_SIZE - 1

#define SAFE_ACCESS(x) x &(MAX_BUFFER_SIZE - 1)
#define CHAR_POINTER(x) (char *)&x

stain void write_u8(uint8_t *, uint64_t *, uint8_t);
stain void write_u16(uint8_t *, uint64_t *, uint16_t);
stain void write_u32(uint8_t *, uint64_t *, uint32_t);
stain void write_u64(uint8_t *, uint64_t *, uint64_t);
stain void write_s8(uint8_t *, uint64_t *, int8_t);
stain void write_s16(uint8_t *, uint64_t *, int16_t);
stain void write_s32(uint8_t *, uint64_t *, int32_t);
stain void write_s64(uint8_t *, uint64_t *, int64_t);
stain void write_ipv6(uint8_t *, uint64_t *, uint32_t ipv6[16]);
stain uint16_t write_str(uint8_t *, uint64_t *, unsigned long, uint16_t,
                         enum memory);
stain uint16_t write_byte_arr(uint8_t *, uint64_t *, unsigned long, uint16_t,
                              enum memory);

stain void write_u8(uint8_t *buf, uint64_t *pos, uint8_t data) {
  *((uint8_t *)&buf[SAFE_ACCESS(*pos)]) = data;
  *pos += sizeof(uint8_t);
};

stain void write_u16(uint8_t *buf, uint64_t *pos, uint16_t data) {
  *((uint16_t *)&buf[SAFE_ACCESS(*pos)]) = data;
  *pos += sizeof(uint16_t);
};

stain void write_u32(uint8_t *buf, uint64_t *pos, uint32_t data) {
  *((uint32_t *)&buf[SAFE_ACCESS(*pos)]) = data;
  *pos += sizeof(uint32_t);
};

stain void write_u64(uint8_t *buf, uint64_t *pos, uint64_t data) {
  *((uint64_t *)&buf[SAFE_ACCESS(*pos)]) = data;
  *pos += sizeof(uint64_t);
};

stain void write_s8(uint8_t *buf, uint64_t *pos, int8_t data) {
  *((int8_t *)&buf[SAFE_ACCESS(*pos)]) = data;
  *pos += sizeof(int8_t);
};

stain void write_s16(uint8_t *buf, uint64_t *pos, int16_t data) {
  *((int16_t *)&buf[SAFE_ACCESS(*pos)]) = data;
  *pos += sizeof(int16_t);
};

stain void write_s32(uint8_t *buf, uint64_t *pos, int32_t data) {
  *((int32_t *)&buf[SAFE_ACCESS(*pos)]) = data;
  *pos += sizeof(int32_t);
}

stain void write_s64(uint8_t *buf, uint64_t *pos, int64_t data) {
  *((int64_t *)&buf[SAFE_ACCESS(*pos)]) = data;
  *pos += sizeof(int64_t);
}

stain void write_ipv6(uint8_t *buf, uint64_t *pos, uint32_t ipv6[4]) {
  __builtin_memcpy(&buf[SAFE_ACCESS(*pos)], ipv6, 16);
  *pos += 16;
}

stain uint16_t write_str(uint8_t *buf, uint64_t *pos, unsigned long data_ptr, uint16_t n, enum memory mr) {
  int written_bytes = 0;

  uint16_t *len = ((uint16_t *)&buf[SAFE_ACCESS(*pos)]);
  *len = 0;
  *pos += sizeof(uint16_t);

  if (mr == USER) {
    written_bytes =
        bpf_probe_read_user_str(&buf[SAFE_ACCESS(*pos)], n, (char *)data_ptr);
  } else {
    written_bytes =
        bpf_probe_read_kernel_str(&buf[SAFE_ACCESS(*pos)], n, (char *)data_ptr);
  }

  if (written_bytes <= 0) {
    return 0;
  }

  *len = written_bytes;
  *pos += written_bytes;

  return (uint16_t)written_bytes;
};

#define MAX_CHARBUF_POINTERS 16

stain int write_str_arr(uint8_t *buf, uint64_t *pos, u64 reserved_space, char **data_ptr, uint16_t n) {  
  uint16_t *len = ((uint16_t *)&buf[SAFE_ACCESS(*pos)]);
  *len = 0;
  *pos += sizeof(uint16_t);

  u8 space = 32;
  unsigned long charbuf_pointer = 0;
  uint16_t arg_len = 0;
  uint16_t total_len = 0;
  uint16_t initial_pos = *pos;

#pragma unroll
  for (; n < MAX_CHARBUF_POINTERS; ++n) {
    bpf_probe_read_user(&charbuf_pointer, sizeof(charbuf_pointer), &data_ptr[n]);
    if (!charbuf_pointer)
      break;

    if (total_len!=0) {
      write_u8(buf, pos, space);
      total_len++;
    }

    arg_len = bpf_probe_read_user_str(&buf[SAFE_ACCESS(*pos)], MAX_STRING_SIZE, (char *)charbuf_pointer);
    if (arg_len <= 0)
      break;

    total_len += arg_len;
    *pos += arg_len & (MAX_STRING_SIZE - 1);
  }
  
  total_len = total_len & (MAX_STRING_SIZE - 1);
  *len = total_len;
  *pos = initial_pos + total_len;

  return total_len;
}

stain uint16_t write_byte_arr(uint8_t *buf, uint64_t *pos, unsigned long data_ptr, uint16_t n, enum memory mr) {
  int written_bytes = 0;
  
  uint16_t *len = ((uint16_t *)&buf[SAFE_ACCESS(*pos)]);
  *len = 0;
  *pos += sizeof(uint16_t);

  if (mr == USER) {
    written_bytes = bpf_probe_read_user_str(&buf[SAFE_ACCESS(*pos)], n, (void *)data_ptr);
  } else {
    written_bytes = bpf_probe_read_kernel_str(&buf[SAFE_ACCESS(*pos)], n, (void *)data_ptr);
  }

  bpf_printk("write %d", written_bytes);
  if (written_bytes <= 0) {
    return 0;
  }

  *len = written_bytes;
  *pos += written_bytes;

  return n;
};

#endif