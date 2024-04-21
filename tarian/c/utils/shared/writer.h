// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

#ifndef __UTILS_SHARED_WRITER_H__
#define __UTILS_SHARED_WRITER_H__

enum memory { KERNEL = 0, USER = 1 };

stain void write_u8(uint8_t *, uint64_t *, uint8_t);
stain void write_u16(uint8_t *, uint64_t *, uint16_t);
stain void write_u32(uint8_t *, uint64_t *, uint32_t);
stain void write_u64(uint8_t *, uint64_t *, uint64_t);
stain void write_s8(uint8_t *, uint64_t *, int8_t);
stain void write_s16(uint8_t *, uint64_t *, int16_t);
stain void write_s32(uint8_t *, uint64_t *, int32_t);
stain void write_s64(uint8_t *, uint64_t *, int64_t);
stain void write_ipv6(uint8_t *, uint64_t *, uint32_t ipv6[16]);

stain int16_t write_str(uint8_t *, uint64_t *, unsigned long, uint16_t, enum memory);
stain int16_t write_byte_arr(uint8_t *, uint64_t *, unsigned long, uint16_t, enum memory);

stain void write_u8(uint8_t *buf, uint64_t *pos, uint8_t data) {
  *((uint8_t *)&buf[SAFE_ACCESS_PARAM(*pos)]) = data;
  *pos += sizeof(uint8_t);
};

stain void write_u16(uint8_t *buf, uint64_t *pos, uint16_t data) {
  *((uint16_t *)&buf[SAFE_ACCESS_PARAM(*pos)]) = data;
  *pos += sizeof(uint16_t);
};

stain void write_u32(uint8_t *buf, uint64_t *pos, uint32_t data) {
  *((uint32_t *)&buf[SAFE_ACCESS_PARAM(*pos)]) = data;
  *pos += sizeof(uint32_t);
};

stain void write_u64(uint8_t *buf, uint64_t *pos, uint64_t data) {
  *((uint64_t *)&buf[SAFE_ACCESS_PARAM(*pos)]) = data;
  *pos += sizeof(uint64_t);
};

stain void write_s8(uint8_t *buf, uint64_t *pos, int8_t data) {
  *((int8_t *)&buf[SAFE_ACCESS_PARAM(*pos)]) = data;
  *pos += sizeof(int8_t);
};

stain void write_s16(uint8_t *buf, uint64_t *pos, int16_t data) {
  *((int16_t *)&buf[SAFE_ACCESS_PARAM(*pos)]) = data;
  *pos += sizeof(int16_t);
};

stain void write_s32(uint8_t *buf, uint64_t *pos, int32_t data) {
  *((int32_t *)&buf[SAFE_ACCESS_PARAM(*pos)]) = data;
  *pos += sizeof(int32_t);
}

stain void write_s64(uint8_t *buf, uint64_t *pos, int64_t data) {
  *((int64_t *)&buf[SAFE_ACCESS_PARAM(*pos)]) = data;
  *pos += sizeof(int64_t);
}

stain void write_ipv6(uint8_t *buf, uint64_t *pos, uint32_t ipv6[4]) {
  __builtin_memcpy(&buf[SAFE_ACCESS_PARAM(*pos)], ipv6, 16);
  *pos += 16;
}

stain int16_t write_str(uint8_t *buf, uint64_t *pos, unsigned long data_ptr, uint16_t wlen,enum memory mr) {
  /*
    [<len><str....>]
  */
  uint16_t *len = ((uint16_t *)&buf[SAFE_ACCESS_PARAM(*pos)]);
  *len = 0;
  *pos += sizeof(uint16_t);

  int written_bytes = 0;
  int limit = wlen;

  switch (mr) {
  case USER:
    written_bytes = bpf_probe_read_user_str(&buf[SAFE_ACCESS_PARAM(*pos)], (limit >= MAX_STRING_SIZE? MAX_STRING_SIZE: SAFE_STRING_LEN(limit)), (char *)data_ptr);
    break;
  case KERNEL:
    written_bytes = bpf_probe_read_kernel_str(&buf[SAFE_ACCESS_PARAM(*pos)], (limit >= MAX_STRING_SIZE? MAX_STRING_SIZE: SAFE_STRING_LEN(limit)), (char *)data_ptr);
    break;
  }

  if (written_bytes <= 0)
    return -1;
  
  *len = written_bytes;
  if (written_bytes == MAX_STRING_SIZE) 
    *pos += MAX_STRING_SIZE;
  else 
    *pos += SAFE_STRING_LEN(written_bytes);

  return (int16_t)written_bytes;
};

stain int16_t write_byte_arr(uint8_t *buf, uint64_t *pos, unsigned long data_ptr, uint16_t n, enum memory mr) {
  /*
    [<len><str....>]
  */
  uint16_t *len = ((uint16_t *)&buf[SAFE_ACCESS_PARAM(*pos)]);
  *len = 0;
  *pos += sizeof(uint16_t);

  uint16_t limit = MAX_STRING_SIZE;
  if (n < limit)
    limit = n;

  long read_status = 0;

  switch (mr) {
  case USER:
    read_status = bpf_probe_read_user(&buf[SAFE_ACCESS_PARAM(*pos)], (limit >= MAX_STRING_SIZE? MAX_STRING_SIZE: SAFE_STRING_LEN(limit)), (void *)data_ptr);
    break;
  case KERNEL:
    read_status = bpf_probe_read_kernel(&buf[SAFE_ACCESS_PARAM(*pos)], (limit >= MAX_STRING_SIZE? MAX_STRING_SIZE: SAFE_STRING_LEN(limit)), (void *)data_ptr);
    break;
  }

  if (read_status != 0)
    return -1;

  *len = limit;
  if (limit == MAX_STRING_SIZE) 
    *pos += MAX_STRING_SIZE;
  else 
    *pos += SAFE_STRING_LEN(limit);

  return (int16_t)*len;
};

#endif