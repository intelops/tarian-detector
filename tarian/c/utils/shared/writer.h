#ifndef __UTILS_SHARED_WRITER_H__
#define __UTILS_SHARED_WRITER_H__

enum memory { KERNEL = 0, USER = 1 };

#define MAX_EVENT_SIZE 64 * 1024
#define MAX_PARAM_SIZE MAX_EVENT_SIZE - 1

#define SAFE_ACCESS(x) x &(MAX_PARAM_SIZE)
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
stain uint16_t write_str(uint8_t *, uint64_t *, unsigned long, uint16_t, enum memory);
stain uint16_t write_byte_arr(uint8_t *, uint64_t *, unsigned long, uint16_t, enum memory);

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
  /*
    [len..str....]
  */

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
  /*
    [len..str....]
  */

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
  /*
    [len..str....]
  */
  int written_bytes = 0;
  
  uint16_t *len = ((uint16_t *)&buf[SAFE_ACCESS(*pos)]);
  *len = 0;
  *pos += sizeof(uint16_t);

  if (mr == USER) {
    written_bytes = bpf_probe_read_user_str(&buf[SAFE_ACCESS(*pos)], n, (void *)data_ptr);
  } else {
    written_bytes = bpf_probe_read_kernel_str(&buf[SAFE_ACCESS(*pos)], n, (void *)data_ptr);
  }

  if (written_bytes <= 0) {
    return 0;
  }

  *len = written_bytes;
  *pos += written_bytes;

  return n;
};

#define MAX_IOVEC_COUNT 32
stain void write_iovec_arr(uint8_t *buf, uint64_t *pos, unsigned long iov_ptr, unsigned long iov_count) {
  /*
    [[len]...str...]
  */

  uint16_t *len = ((uint16_t *)&buf[SAFE_ACCESS(*pos)]);
  *len = 0;
  *pos += sizeof(uint16_t);
  
  uint32_t total_len = 0;
  uint16_t initial_pos = *pos;

  uint32_t total_iovec_size = iov_count * bpf_core_type_size(struct iovec);
  if (bpf_probe_read_user((void *)&buf[MAX_PARAM_SIZE], SAFE_ACCESS(total_iovec_size), (void *)iov_ptr) != 0) return;

  const struct iovec *iovs = (const struct iovec *)&buf[MAX_PARAM_SIZE];
  
  for (int i = 0; i < MAX_IOVEC_COUNT; i++) {
    if (i == (iov_count & (MAX_IOVEC_COUNT - 1))) break;

    uint16_t byte_read = bpf_probe_read_user(&buf[SAFE_ACCESS(*pos)], SAFE_ACCESS(iovs[i].iov_len), iovs[i].iov_base);
    if (byte_read != 0) continue;

    *pos += iovs[i].iov_len & (MAX_STRING_SIZE - 1);
    total_len += iovs[i].iov_len;
  }

  total_len = total_len &  (MAX_STRING_SIZE - 1);
  *len = total_len;
  *pos = initial_pos + total_len;
}

#define MAX_UNIX_SOCKET_PATH 108 + 1
stain void write_sockaddr(uint8_t *buf, uint64_t *pos, unsigned long data_ptr, uint16_t addrlen) {
  if (bpf_probe_read((void *)&buf[MAX_PARAM_SIZE], SAFE_ACCESS(addrlen), (void *)data_ptr) != 0) return;
  
  struct sockaddr *sockaddr = (struct sockaddr *)&buf[MAX_PARAM_SIZE];
  uint16_t socket_family = sockaddr->sa_family;

  switch (socket_family) {
    case AF_INET: {
      struct sockaddr_in *sockaddr_in = (struct sockaddr_in *)sockaddr;

      uint32_t ipv4 = sockaddr_in->sin_addr.s_addr;
      uint16_t port = sockaddr_in->sin_port;

      write_u8(buf, pos, socket_family);      
      write_u32(buf, pos, ipv4);
      write_u16(buf, pos, port);
      break;
    }
    case  AF_INET6: {
      struct sockaddr_in6 *sockaddr_in6 = (struct sockaddr_in6 *)sockaddr;
      
      uint32_t ipv6[4] = {0, 0, 0, 0};
      __builtin_memcpy(&ipv6, sockaddr_in6->sin6_addr.in6_u.u6_addr32, 16);
      
      uint16_t port = sockaddr_in6->sin6_port;

      write_u8(buf, pos, socket_family);      
      write_ipv6(buf, pos, ipv6);
      write_u16(buf, pos,  port); 
      break;
    }
    case  AF_UNIX: {
      struct sockaddr_un *sockaddr_un = (struct sockaddr_un *)sockaddr;

      unsigned long start_reading_point;
      char first_path_byte = *(char *)sockaddr_un->sun_path;
      if(first_path_byte == '\0')
      {
        start_reading_point = (unsigned long)sockaddr_un->sun_path + 1;
      }
      else
      {
        start_reading_point = (unsigned long)sockaddr_un->sun_path;
      }

      write_u8(buf, pos, socket_family);      
      write_str(buf, pos, start_reading_point, MAX_UNIX_SOCKET_PATH, KERNEL);
      break;
    }
  }
}

#endif