// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

#ifndef __UTLIS_SHARED_CONSTANTS_H__
#define __UTLIS_SHARED_CONSTANTS_H__

#define MAX_NODE_FIELD_SIZE 65 /* 65B */
#define MAX_STRING_SIZE 4096   /* 4KB */
#define MAX_TARIAN_PATH 4096   /* 4KB */
#define MAX_CPU_BUFFER_SIZE 1024 * 32 /* 32KB */

#define MAX_EVENT_SIZE 32 * 1024 /* 32KB */
#define MAX_PARAM_SIZE MAX_EVENT_SIZE - 1 /* 32KB */

#define TASK_COMM_LEN 16
#define MAX_CHARBUF_POINTERS 128
#define MAX_UNIX_SOCKET_PATH 108 + 1 /* for NULL termination */

#define MAX_IOVEC_COUNT 32
#define SAFE_IOVEC_COUNT(x) (x) & (MAX_IOVEC_COUNT - 1)

#define SAFE_TARIAN_PATH_LEN(x) (x) & (MAX_TARIAN_PATH - 1)
#define SAFE_STRING_LEN(x) x & (MAX_STRING_SIZE - 1)
#define SAFE_ACCESS_PARAM(x) (x) & (MAX_PARAM_SIZE)
#define SAFE_ACCESS_CPU_BUFFER(x) (x) & (MAX_CPU_BUFFER_SIZE - 1)
#define SAFE_ACCESS_EVENT(x) (x) & (MAX_EVENT_SIZE - 1)

#define MAX_SCRATCH_SPACE_ARRAY_LEN 1
#define MAX_SCRATCH_SPACE_SIZE 1024 * 8 /* 8KB */
#define SCRATCH_SPACE_HALF_INDEX (MAX_SCRATCH_SPACE_SIZE)/2
#define SAFE_ACCESS_SCRATCH_SPACE(x) (x) & ((MAX_SCRATCH_SPACE_SIZE)/2 - 1)

#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE                                                     \
  KERNEL_VERSION(LINUX_VERSION_MAJOR, LINUX_VERSION_MINOR, LINUX_VERSION_PATCH)
#endif

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

#define RINGBUF_MAX_ENTRIES 1024 * 1024 * 128 /* 128MB */
#define ARRAY_OF_MAPS_MAX_ENTRIES 16

#define stain static __always_inline

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0))
#define MAX_NUM_COMPONENTS 48
#else
#define MAX_NUM_COMPONENTS 24
#endif

/**
 * Enumeration of different types of parameters that can be stored in events.
 */
enum tarian_param_type_e {
  /**
   * No data stored.
   */
  TDT_NONE = 0,
  /**
   * 8-bit unsigned integer.
   */
  TDT_U8,
  /**
   * 16-bit unsigned integer.
   */
  TDT_U16,
  /**
   * 32-bit unsigned integer.
   */
  TDT_U32,
  /**
   * 64-bit unsigned integer.
   */
  TDT_U64,
  /**
   * 8-bit signed integer.
   */
  TDT_S8,
  /**
   * 16-bit signed integer.
   */
  TDT_S16,
  /**
   * 32-bit signed integer.
   */
  TDT_S32,
  /**
   * 64-bit signed integer.
   */
  TDT_S64,
  /**
   * IPv6 address.
   */
  TDT_IPV6,
  /**
   * Null-terminated string. The maximum size is `MAX_STRING_SIZE`.
   */
  TDT_STR,
  /**
   * Array of null-terminated strings. The maximum number of elements is
   * `MAX_CHARBUF_POINTERS`.
   */
  TDT_STR_ARR,
  /**
   * Array of bytes. The maximum size is `MAX_STRING_SIZE`.
   */
  TDT_BYTE_ARR,
  /**
   * Array of `struct iovec`. The maximum number of elements is
   * `MAX_STRING_SIZE`.
   */
  TDT_IOVEC_ARR,
  /**
   * Socket address.
   */
  TDT_SOCKADDR,
};

/**
 * Enumeration of Tarian events.
 */
typedef enum tarian_events_e {
  TDE_SYSCALL_EXECVE_E = 2, // Execve event - entry.
  TDE_SYSCALL_EXECVE_R,    // Execve event - exit.

  TDE_SYSCALL_EXECVEAT_E,  // Execveat event - entry.
  TDE_SYSCALL_EXECVEAT_R,  // Execveat event - exit.

  TDE_SYSCALL_CLONE_E,     // Clone event - entry.
  TDE_SYSCALL_CLONE_R,     // Clone event - exit.

  TDE_SYSCALL_CLOSE_E,     // Close event - entry.
  TDE_SYSCALL_CLOSE_R,     // Close event - exit.

  TDE_SYSCALL_READ_E,      // Read event - entry.
  TDE_SYSCALL_READ_R,      // Read event - exit.

  TDE_SYSCALL_WRITE_E,     // Write event - entry.
  TDE_SYSCALL_WRITE_R,     // Write event - exit.

  TDE_SYSCALL_OPEN_E,      // Open event - entry.
  TDE_SYSCALL_OPEN_R,      // Open event - exit.

  TDE_SYSCALL_READV_E,     // Readv event - entry.
  TDE_SYSCALL_READV_R,     // Readv event - exit.

  TDE_SYSCALL_WRITEV_E,    // Writev event - entry.
  TDE_SYSCALL_WRITEV_R,    // Writev event - exit.

  TDE_SYSCALL_OPENAT_E,    // Openat event - entry.
  TDE_SYSCALL_OPENAT_R,    // Openat event - exit.

  TDE_SYSCALL_OPENAT2_E,   // Openat2 event - entry.
  TDE_SYSCALL_OPENAT2_R,   // Openat2 event - exit.

  TDE_SYSCALL_LISTEN_E,    // Listen event - entry.
  TDE_SYSCALL_LISTEN_R,    // Listen event - exit.

  TDE_SYSCALL_SOCKET_E,    // Socket event - entry.
  TDE_SYSCALL_SOCKET_R,    // Socket event - exit.

  TDE_SYSCALL_ACCEPT_E,    // Accept event - entry.
  TDE_SYSCALL_ACCEPT_R,    // Accept event - exit.

  TDE_SYSCALL_BIND_E,      // Bind event - entry.
  TDE_SYSCALL_BIND_R,      // Bind event - exit.

  TDE_SYSCALL_CONNECT_E,   // Connect event - entry.
  TDE_SYSCALL_CONNECT_R,   // Connect event - exit.
} tarian_event_code;

/*****
 * Event Data Size - START
 *
 * sizeof tarian meta data for each event
 *
 * Maximum string size for directory and executable: MAX_STRING_SIZE
 * Parameter size: PARAM_SIZE
 *
 * Each event data size is defined as:
 * TDS_<event name>_<entry(E)/exit(R)>
 *
 ****************************************************************************/

/**
 * Size of variable length arguments.
 *
 * The size of an argument is stored as a uint16_t,
 * immediately preceding the argument itself. The
 * uint16_t is used to indicate how much data should
 * be read for the given argument.
 *
 * For example, if we have a buffer containing the
 * bytes [0x00, 0x05, 'h', 'e', 'l', 'l', 'o'],
 * the argument "hello" would be stored in the buffer
 * as [0x00, 0x05, 'h', 'e', 'l', 'l', 'o']. The first
 * two bytes, 0x00, 0x05, indicate that the argument
 * "hello" is 5 bytes long.
 *
 * When reading the argument from the buffer, we would
 * first read the uint16_t value (0x00, 0x05) to determine
 * that the argument is 5 bytes long. Then, we would read the
 * next 5 bytes, which would be ['h', 'e', 'l', 'l', 'o'],
 * to get the entire argument "hello".
 */
#define PARAM_SIZE sizeof(uint16_t)

/**
 * Tarian Metadata 
 * - sizeof(tarian_meta_data_t) - 505
 * - directory - 4098
 * - executable - 4098
 * Total size - 8701 bytes
 */
#define TMD_SIZE (sizeof(tarian_meta_data_t) + (PARAM_SIZE + MAX_TARIAN_PATH) * 2)

/**
 * Execve entry
 * - metadata - 8701
 * - filename - 4098
 * - argv - 4098
 * - envp - 4098
 * Total size: 20995 bytes
 */
#define TDS_EXECVE_E (TMD_SIZE + (PARAM_SIZE + MAX_STRING_SIZE) * 3)

/**
 * Execve exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
 */
#define TDS_EXECVE_R (TMD_SIZE + sizeof(int32_t))

/** 
 *  Execveat entry
 *  - metadata - 8701
 *  - fd - 4
 *  - filename - 4098
 *  - argv - 4098
 *  - envp - 4098
 *  - flags - 4
 *  Total size: 21003 bytes
 */
#define TDS_EXECVEAT_E (TMD_SIZE + (sizeof(int32_t) * 2) + (PARAM_SIZE + MAX_STRING_SIZE) * 3)

/**
 *  Execveat exit
 *  - metadata - 8701
 *  - return value - 4
 *  Total size: 8705 bytes
 */
#define TDS_EXECVEAT_R (TMD_SIZE + sizeof(int32_t))

/** 
 * Clone entry
 * - metadata - 8701
 * - clone_flags - 8
 * - newsp - 8
 * - parent_tidptr - 4
 * - child_tidptr - 4
 * - tls - 8
 * Total size: 8733 bytes
 */
#define TDS_CLONE_E (TMD_SIZE + sizeof(uint64_t) * 3 + sizeof(int32_t) * 2)

/** 
 * Clone exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
 */
#define TDS_CLONE_R (TMD_SIZE + sizeof(int32_t))

/**
 * Close entry 
 * - metadata - 8701
 * - file descriptor - 4
 * Total size: 8705 bytes
 */
#define TDS_CLOSE_E (TMD_SIZE + sizeof(int32_t))

/** 
 * Close exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
 */
#define TDS_CLOSE_R (TMD_SIZE + sizeof(int32_t))

/** 
 * Read entry
 * - metadata - 8701
 * - file descriptor - 4
 * - buf - 4098
 * - count - 4
 * Total size: 12807 bytes
 */
#define TDS_READ_E (TMD_SIZE + sizeof(int32_t) + (PARAM_SIZE + MAX_STRING_SIZE) + sizeof(uint32_t))

/**
 *  READ exit
 *  - metadata - 8701
 *  - return value - 8
 *  Total size: 8709 bytes
 */
#define TDS_READ_R (TMD_SIZE + sizeof(long))

/**
 * Write entry
 * - metadata - 8701
 * - file descriptor - 4
 * - buf - 4098
 * - count - 4
 * Total size: 12807 bytes
*/
#define TDS_WRITE_E (TMD_SIZE + sizeof(int32_t) + (PARAM_SIZE + MAX_STRING_SIZE) + sizeof(uint32_t))

/**
 *  Write exit
 *  - metadata - 8701
 *  - return value - 8
 *  Total size: 8709 bytes
 */
#define TDS_WRITE_R (TMD_SIZE + sizeof(long))

/**
 * Open entry
 * - metadata - 8701
 * - filename - 4098
 * - flags - 4
 * - mode - 4
 * Total size: 12807 bytes
 */
#define TDS_OPEN_E (TMD_SIZE + (PARAM_SIZE + MAX_STRING_SIZE) + sizeof(int32_t) + sizeof(uint32_t))

/** 
 * Open exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
 */
#define TDS_OPEN_R (TMD_SIZE + sizeof(int32_t))

/**
 * Readv entry
 * - metadata - 8701
 * - fd - 4
 * - vec - 4098
 * - vlen - 4
 * Total size: 12807 bytes
*/
#define TDS_READV_E (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_STRING_SIZE))

/**
 * Readv exit
 * - metadata - 8701
 * - return value - 8
 * Total size: 8709 bytes
*/
#define TDS_READV_R (TMD_SIZE + sizeof(long))

/**
 * Writev entry
 * - metadata - 8701
 * - fd - 4
 * - vec - 4098
 * - vlen - 4
 * Total size: 12807 bytes
*/
#define TDS_WRITEV_E (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_STRING_SIZE))

/**
 * Writev exit
 * - metadata - 8701
 * - return value - 8
 * Total size: 8709 bytes
*/
#define TDS_WRITEV_R (TMD_SIZE + sizeof(long))

/** 
 * Openat entry
 * - metadata - 8701
 * - dirfd - 4
 * - filename - 4098
 * - flags - 4
 * - mode - 4
 * Total size: 12811 bytes
*/
#define TDS_OPENAT_E (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_STRING_SIZE) + sizeof(uint32_t))

/**
 * Openat exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
*/
#define TDS_OPENAT_R (TMD_SIZE + sizeof(int32_t))

/**
 * Openat2 entry
 * - metadata - 8701
 * - dirfd - 4
 * - filename - 4098
 * - flag - 8
 * - mode - 8
 * - resolve - 8
 * - usize - 4
 * Total size: 12831 bytes
*/
#define TDS_OPENAT2_E (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_STRING_SIZE) + sizeof(uint64_t) * 3)

/**
 * Openat2 exit
 * - metadata - 8701
 * - return value - 8
 * Total size: 8709 bytes
*/
#define TDS_OPENAT2_R (TMD_SIZE + sizeof(long))

/**
 * Listen entry
 * - metadata - 8701
 * - fd - 4
 * - backlog - 4
 * Total size: 8709 bytes
*/
#define TDS_LISTEN_E (TMD_SIZE + sizeof(int32_t) * 2)

/**
 * Listen exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
*/
#define TDS_LISTEN_R (TMD_SIZE + sizeof(int32_t))

/**
 * Socket entry
 * - metadata - 8701
 * - family - 4
 * - type - 4
 * - protocol - 4
 * Total size: 8713
*/
#define TDS_SOCKET_E (TMD_SIZE + sizeof(int32_t) * 3)

/**
 * Socket exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
*/
#define TDS_SOCKET_R (TMD_SIZE + sizeof(int32_t))

/**
 * Accept entry
 * - metadata - 8701
 * - fd - 4
 * - upeer_sockaddr - 111
 * - upeer_addrlen - 4
 * Total size: 8820 bytes
*/
#define TDS_ACCEPT_E (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_UNIX_SOCKET_PATH))

/**
 * Accept exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
*/
#define TDS_ACCEPT_R (TMD_SIZE + sizeof(int32_t))

/**
 * Bind entry
 * - metadata - 8701
 * - fd - 4
 * - umyaddr - 111
 * - addrlen - 4
 * Total size: 8820 bytes
*/
#define TDS_BIND_E (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_UNIX_SOCKET_PATH))

/**
 * Bind exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
*/
#define TDS_BIND_R (TMD_SIZE + sizeof(int32_t))

/**
 * Connect entry
 * - metadata - 8701
 * - fd - 4
 * - uservaddr - 111
 * - addrlen - 4
 * Total size: 8820 bytes
*/
#define TDS_CONNECT_E (TMD_SIZE + sizeof(int32_t) * 2 + MAX_UNIX_SOCKET_PATH + PARAM_SIZE)

/**
 * Connect exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
*/
#define TDS_CONNECT_R (TMD_SIZE + sizeof(int32_t))
/*********************************** Event Data Size - END ************************************/

#endif