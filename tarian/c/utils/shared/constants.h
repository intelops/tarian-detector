// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

#ifndef __UTLIS_SHARED_CONSTANTS_H__
#define __UTLIS_SHARED_CONSTANTS_H__

/**
 * The maximum size is set to 32KB due to the limitations of
 * `BPF_MAP_TYPE_PERCPU_ARRAY`. For more information, refer to the following
 * resources:
 * - Discussion on iovisor/bcc -
 * https://github.com/iovisor/bcc/issues/2519#issuecomment-534359316
 * - Linux Source Code -
 * https://github.com/torvalds/linux/blob/09688c0166e76ce2fb85e86b9d99be8b0084cdf9/mm/percpu.c#L1756
 */
#define MAX_CPU_BUFFER_SIZE 1024 * 32

/**
 * Maximum size of the tarian event.
 *
 * This constant defines the maximum size an event can be. Events are stored in
 * a common buffer that is sent to userspace using bpf maps. The
 * size is set to 32KB to ensure that events are not too large and can be
 * sent to userspace successfully.
 */
#define MAX_TARIAN_EVENT_SIZE 1024 * 32

/**
 * Maximum size of a parameter that can be stored in an event.
 *
 * This constant defines the maximum size a parameter can be. It is used to
 * determine how much space is allocated for parameters in events. The value
 * is set to `MAX_TARIAN_EVENT_SIZE - 1` to ensure that the parameter will
 * always fit in the event.
 */
#define MAX_TARIAN_PARAM_SIZE MAX_TARIAN_EVENT_SIZE - 1

/**
 * @brief Adjusts a given length value to ensure it doesn't exceed
 * `MAX_TARIAN_PARAM_SIZE`.
 *
 * This is achieved by applying a bitwise AND operation with
 * `(MAX_TARIAN_PARAM_SIZE - 1)`. This can help prevent potential buffer
 * overflows when the length is used to size a buffer, but it does not actually
 * check or limit the length of any data.
 *
 * @param x The original length value to be adjusted.
 * @return The adjusted length value, which will be less than or equal to
 * `MAX_TARIAN_PARAM_SIZE`.
 */
#define SAFE_ACCESS_PARAM(x) (x) & (MAX_TARIAN_PARAM_SIZE)

/**
 * The maximum size for a string parameter written to a buffer for userspace.
 *
 * This constant defines the maximum size a string parameter can be. It is used
 * to determine how much space is allocated for strings in events. The value is
 * set to 4096 to ensure that strings are not too large and can be sent to
 * userspace successfully.
 */
#define MAX_STRING_SIZE 4096

/**
 * @brief Adjusts a given length value to ensure it doesn't exceed
 * `MAX_STRING_SIZE`.
 *
 * This is achieved by applying a bitwise AND operation with `(MAX_STRING_SIZE -
 * 1)`. This can help prevent potential buffer overflows when the length is used
 * to size a buffer, but it does not actually check or limit the length of any
 * string.
 *
 * @param x The original length value to be adjusted.
 * @return The adjusted length value, which will be less than `MAX_STRING_SIZE`.
 */
#define SAFE_STRING_LEN(x) x &(MAX_STRING_SIZE - 1)

/**
 * @brief The maximum length for a task command string.
 */
#define TASK_COMM_LEN 16

/**
 * @brief The maximum length for a UNIX socket path.
 *
 * This macro sets the maximum length to 109, accounting for the maximum UNIX
 * socket path length (108 bytes) and an additional byte for the NULL
 * termination character.
 */
#define MAX_UNIX_SOCKET_PATH 108 + 1

/**
 * @brief Defines the maximum number of iterations for looping over a char**
 * parameter.
 *
 * This constant defines the maximum number of times the loop will iterate when
 * processing a char** parameter. The loop is used to read strings from all
 * elements, up to a maximum combined length of 4096 characters.
 */
#define MAX_CHARBUF_POINTERS 64

/**
 * @brief Defines the maximum number of iterations for looping over an array of
 * struct iovec.
 *
 * This constant defines the maximum number of times the loop will iterate when
 * processing an array of iovecs. The loop is used to read iovecs from all
 * elements, up to a maximum combined length of 4096 iovecs.
 */
#define MAX_IOVEC_COUNT 32

/**
 * @brief Adjusts a given length value to ensure it doesn't exceed
 * `MAX_IOVEC_COUNT`.
 *
 * This is achieved by applying a bitwise AND operation with `(MAX_IOVEC_COUNT -
 * 1)`. This can help prevent potential buffer overflows when the length is used
 * to size a buffer, but it does not actually check or limit the length of any
 * iovec.
 *
 * @param x The original length value to be adjusted.
 * @return The adjusted length value, which will be less than `MAX_IOVEC_COUNT`.
 */
#define SAFE_IOVEC_COUNT(x) (x) & (MAX_IOVEC_COUNT - 1)

/**
 * @brief Defines the maximum number of elements for the `scratch_space`
 * BPF_MAP_TYPE_PERCPU_ARRAY map.
 *
 * This constant defines the maximum number of elements in a
 * BPF_MAP_TYPE_PERCPU_ARRAY map named `scratch_space`. The value is set to `1`,
 * meaning the `scratch_space` map can hold one element per CPU.
 */
#define MAX_SCRATCH_SPACE_ARRAY_LEN 1

/**
 * @brief Defines the maximum size of each element in the `scratch_space` map.
 *
 * This constant defines the maximum size, in bytes, of each element in the
 * BPF_MAP_TYPE_PERCPU_ARRAY `scratch_space` map. The value is set to `1024 *
 * 8`, meaning each element in the `scratch_space` map can hold up to `8192
 * bytes` of data.
 */
#define MAX_SCRATCH_SPACE_SIZE 1024 * 8

/**
 * @brief Defines the half index of the `scratch_space` map.
 *
 * This constant defines the half index of the `scratch_space` map.
 * The value is set to `MAX_SCRATCH_SPACE_SIZE/2`, meaning it represents the
 * midpoint in the `scratch_space` map.
 */
#define HALF_SCRATCH_SPACE_SIZE (MAX_SCRATCH_SPACE_SIZE) / 2

/**
 * @brief Adjusts a given length value to ensure it doesn't exceed
 * `HALF_SCRATCH_SPACE_SIZE`.
 *
 * This macro is used to safely access the `scratch_space` map.
 * It takes an index (x) and ensures that the index is within the first half of
 * the `scratch_space` map. This is done by performing a bitwise AND operation
 * with `(HALF_SCRATCH_SPACE_SIZE - 1)`. This prevents out-of-bounds access to
 * the `scratch_space` map.
 *
 * @param x The original length value to be adjusted.
 * @return The adjusted length value, which will be less than
 * `HALF_SCRATCH_SPACE_SIZE`.
 */
#define SAFE_ACCESS_SCRATCH_SPACE(x) (x) & (HALF_SCRATCH_SPACE_SIZE - 1)

#ifndef LINUX_VERSION_CODE
/**
 * @brief Defines the Linux kernel version code.
 *
 * This macro is used to define the Linux kernel version code if it's not
 * already defined. The version code is constructed using the `KERNEL_VERSION`
 * macro with `LINUX_VERSION_MAJOR`, `LINUX_VERSION_MINOR`, and
 * `LINUX_VERSION_PATCH` as arguments.
 *
 * The `KERNEL_VERSION` macro takes three numbers: the major version, the minor
 * version, and the patch level, and combines them into a single number in a way
 * that can be compared with other version numbers using the standard C
 * comparison operators.
 *
 * Note: This macro is typically used in conditional compilation.
 */
#define LINUX_VERSION_CODE                                                     \
  KERNEL_VERSION(LINUX_VERSION_MAJOR, LINUX_VERSION_MINOR, LINUX_VERSION_PATCH)
#endif

/**
 * @brief Defines the address family for Unix domain sockets.
 */
#define AF_UNIX 1

/**
 * @brief Defines the address family for IPv4 Internet protocols.
 */
#define AF_INET 2

/**
 * @brief Defines the address family for IPv6 Internet protocols.
 */
#define AF_INET6 10

/**
 * @brief Defines the maximum number of entries for the ring buffer.
 *
 * This macro is used to specify the maximum number of entries that the ring
 * buffer can hold. The value is set to 1024 * 1024 * 128, meaning the ring
 * buffer can hold up to 128MB of data.
 */
#define RINGBUF_MAX_ENTRIES 1024 * 1024 * 128

/**
 * @brief Defines the maximum number of entries for an array of maps.
 *
 * This macro is used to specify the maximum number of entries that an array of
 * maps can hold. The value is set to 16, meaning the array of maps can hold up
 * to 16 map entries.
 */
#define ARRAY_OF_MAPS_MAX_ENTRIES 16

/**
 * @brief A convenience macro for declaring functions as static and always
 * inline.
 *
 * This macro is a shorthand for the `static __always_inline` function specifier
 * combination. Functions declared with `stain` are static, meaning they have
 * internal linkage, and are always inlined by the compiler, which can
 * potentially optimize the code.
 */
#define stain static __always_inline

/**
 * @brief Defines the maximum number of components based on the Linux kernel
 * version.
 *
 * This macro is used to specify the maximum number of components that can be
 * handled. If the Linux kernel version is 5.2.0 or later, the maximum number of
 * components is set to 48. For earlier versions of the Linux kernel, the
 * maximum number of components is set to 24.
 *
 * Note: This macro is typically used in conditional compilation based on the
 * Linux kernel version.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0))
#define MAX_NUM_COMPONENTS 48
#else
#define MAX_NUM_COMPONENTS 24
#endif

/**
 * @brief Defines the types of parameters that can be used in Tarian.
 *
 * This enumeration is used to specify the type of a parameter in Tarian.
 * Each type corresponds to a specific kind of data that can be handled in
 * buffer.
 */
enum tarian_param_type_e {
  /**
   * @brief No data stored.
   *
   * This type indicates that no data is stored. It is used as a placeholder
   * in the Tarian parameter list to indicate that there is no data for that
   * specific parameter.
   */
  TDT_NONE = 0,
  /**
   * 8-bit unsigned integer.
   *
   * This type is used to store a 8-bit unsigned integer.
   */
  TDT_U8,
  /**
   * 16-bit unsigned integer.
   *
   * This type is used to store a 16-bit unsigned integer.
   */
  TDT_U16,
  /**
   * 32-bit unsigned integer.
   *
   * This type is used to store a 32-bit unsigned integer.
   */
  TDT_U32,
  /**
   * 64-bit unsigned integer.
   *
   * This type is used to store a 64-bit unsigned integer.
   */
  TDT_U64,
  /**
   * 8-bit signed integer.
   *
   * This type is used to store a 8-bit signed integer.
   */
  TDT_S8,
  /**
   * 16-bit signed integer.
   *
   * This type is used to store a 16-bit signed integer.
   */
  TDT_S16,
  /**
   * 32-bit signed integer.
   *
   * This type is used to store a 32-bit signed integer.
   */
  TDT_S32,
  /**
   * 64-bit signed integer.
   *
   * This type is used to store a 64-bit signed integer.
   */
  TDT_S64,
  /**
   * IPv6 address.
   *
   * This type is used to store an IPv6 address. The IPv6 address is stored as a
   * byte array with a length of 16 bytes.
   */
  TDT_IPV6,
  /**
   * Null-terminated string. The maximum size is `MAX_STRING_SIZE`.
   *
   * This type is used to store a single NULL-terminated string. The maximum
   * size of the string is `MAX_STRING_SIZE`.
   */
  TDT_STR,
  /**
   * Array of strings seperated by space. The maximum size is `MAX_STRING_SIZE`.
   *
   * This type is used to store an array of NULL-terminated strings. The
   * maximum size of the combined strings is `MAX_STRING_SIZE`. The strings are
   * separated by spaces.
   *
   * For example, if the input is a char** array with the following strings:
   *
   *     {"one", "two", "three", NULL}
   *
   * The resulting string will be:
   *
   *     "one two three"
   *
   * If the combined length of the strings exceeds `MAX_STRING_SIZE`, the
   * resulting string will be truncated.
   */
  TDT_STR_ARR,
  /**
   * Array of bytes.
   *
   * This type is used to store an array of bytes. The maximum size of the
   * array is `MAX_STRING_SIZE`.
   */
  TDT_BYTE_ARR,
  /**
   * Array of `struct iovec`.
   *
   * This type is used to store an array of `struct iovec`. The maximum size of
   * the array is `MAX_STRING_SIZE`.
   *
   * `struct iovec` is a structure that contains a pointer to a buffer and the
   * length of the buffer. This type is used to store an array of `struct
   * iovec`s.
   */
  TDT_IOVEC_ARR,
  /**
   * Socket address.
   *
   * This type is used to store a socket address. The socket address is stored
   * as a byte array..
   */
  TDT_SOCKADDR,
};

/**
 * Enumeration of Tarian events.
 *
 * Each event has an entry event (ending in "_E") and an exit event (ending
 * in "_R").
 *
 * The entry event is triggered when the system call is invoked and the exit
 * event is triggered when the system call returns.
 */
typedef enum tarian_events_e {
  /**
   * Execve event - entry.
   *
   * This event is triggered when a process calls execve(2).
   */
  TDE_SYSCALL_EXECVE_E = 2,
  /**
   * Execve event - exit.
   *
   * This event is triggered when a process calls execve(2) and the call
   * finishes. returns.
   */
  TDE_SYSCALL_EXECVE_R,

  /**
   * Execveat event - entry.
   *
   * This event is triggered when a process calls execveat(2).
   */
  TDE_SYSCALL_EXECVEAT_E,
  /**
   * Execveat event - exit.
   *
   * This event is triggered when a process calls execveat(2) and the call
   * finishes.
   */
  TDE_SYSCALL_EXECVEAT_R,

  /**
   * Clone event - entry.
   *
   * This event is triggered when a process calls clone(2).
   */
  TDE_SYSCALL_CLONE_E,
  /**
   * Clone event - exit.
   *
   * This event is triggered when a process calls clone(2) and the call
   * finishes.
   */
  TDE_SYSCALL_CLONE_R,

  /**
   * Close event - entry.
   *
   * This event is triggered when a process calls close(2).
   */
  TDE_SYSCALL_CLOSE_E,
  /**
   * Close event - exit.
   *
   * This event is triggered when a process calls close(2) and the call
   * finishes.
   */
  TDE_SYSCALL_CLOSE_R,

  /**
   * Read event - entry.
   *
   * This event is triggered when a process calls read(2).
   */
  TDE_SYSCALL_READ_E,
  /**
   * Read event - exit.
   *
   * This event is triggered when a process calls read(2) and the call finishes.
   */
  TDE_SYSCALL_READ_R,

  /**
   * Write event - entry.
   *
   * This event is triggered when a process calls write(2).
   */
  TDE_SYSCALL_WRITE_E,
  /**
   * Write event - exit.
   *
   * This event is triggered when a process calls write(2) and the call
   * finishes.
   */
  TDE_SYSCALL_WRITE_R,

  /**
   * Open event - entry.
   *
   * This event is triggered when a process calls open(2).
   */
  TDE_SYSCALL_OPEN_E,
  /**
   * Open event - exit.
   *
   * This event is triggered when a process calls open(2) and the call finishes.
   */
  TDE_SYSCALL_OPEN_R,

  /**
   * Readv event - entry.
   *
   * This event is triggered when a process calls readv(2).
   */
  TDE_SYSCALL_READV_E,
  /**
   * Readv event - exit.
   *
   * This event is triggered when a process calls readv(2) and the call
   * finishes.
   */
  TDE_SYSCALL_READV_R,

  /**
   * Writev event - entry.
   *
   * This event is triggered when a process calls writev(2).
   */
  TDE_SYSCALL_WRITEV_E,
  /**
   * Writev event - exit.
   *
   * This event is triggered when a process calls writev(2) and the call
   * finishes.
   */
  TDE_SYSCALL_WRITEV_R,

  /**
   * Openat event - entry.
   *
   * This event is triggered when a process calls openat(2).
   */
  TDE_SYSCALL_OPENAT_E,
  /**
   * Openat event - exit.
   *
   * This event is triggered when a process calls openat(2) and the call
   * finishes.
   */
  TDE_SYSCALL_OPENAT_R,

  /**
   * Openat2 event - entry.
   *
   * This event is triggered when a process calls openat2(2).
   */
  TDE_SYSCALL_OPENAT2_E,
  /**
   * Openat2 event - exit.
   *
   * This event is triggered when a process calls openat2(2) and the call
   * finishes.
   */
  TDE_SYSCALL_OPENAT2_R,

  /**
   * Listen event - entry.
   *
   * This event is triggered when a process calls listen(2).
   */
  TDE_SYSCALL_LISTEN_E,
  /**
   * Listen event - exit.
   *
   * This event is triggered when a process calls listen(2) and the call
   * finishes.
   */
  TDE_SYSCALL_LISTEN_R,

  /**
   * Socket event - entry.
   *
   * This event is triggered when a process calls socket(2).
   */
  TDE_SYSCALL_SOCKET_E,
  /**
   * Socket event - exit.
   *
   * This event is triggered when a process calls socket(2) and the call
   * finishes.
   */
  TDE_SYSCALL_SOCKET_R,

  /**
   * Accept event - entry.
   *
   * This event is triggered when a process calls accept(2).
   */
  TDE_SYSCALL_ACCEPT_E,
  /**
   * Accept event - exit.
   *
   * This event is triggered when a process calls accept(2) and the call
   * finishes.
   */
  TDE_SYSCALL_ACCEPT_R,

  /**
   * Bind event - entry.
   *
   * This event is triggered when a process calls bind(2).
   */
  TDE_SYSCALL_BIND_E,
  /**
   * Bind event - exit.
   *
   * This event is triggered when a process calls bind(2) and the call finishes.
   */
  TDE_SYSCALL_BIND_R,

  /**
   * Connect event - entry.
   *
   * This event is triggered when a process calls connect(2).
   */
  TDE_SYSCALL_CONNECT_E,
  /**
   * Connect event - exit.
   *
   * This event is triggered when a process calls connect(2) and the call
   * finishes.
   */
  TDE_SYSCALL_CONNECT_R,
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
#define TMD_SIZE                                                               \
  (sizeof(tarian_meta_data_t) + (PARAM_SIZE + MAX_STRING_SIZE) * 2)

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
#define TDS_EXECVEAT_E                                                         \
  (TMD_SIZE + (sizeof(int32_t) * 2) + (PARAM_SIZE + MAX_STRING_SIZE) * 3)

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
#define TDS_READ_E                                                             \
  (TMD_SIZE + sizeof(int32_t) + (PARAM_SIZE + MAX_STRING_SIZE) +               \
   sizeof(uint32_t))

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
#define TDS_WRITE_E                                                            \
  (TMD_SIZE + sizeof(int32_t) + (PARAM_SIZE + MAX_STRING_SIZE) +               \
   sizeof(uint32_t))

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
#define TDS_OPEN_E                                                             \
  (TMD_SIZE + (PARAM_SIZE + MAX_STRING_SIZE) + sizeof(int32_t) +               \
   sizeof(uint32_t))

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
#define TDS_READV_E                                                            \
  (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_STRING_SIZE))

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
#define TDS_WRITEV_E                                                           \
  (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_STRING_SIZE))

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
#define TDS_OPENAT_E                                                           \
  (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_STRING_SIZE) +           \
   sizeof(uint32_t))

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
#define TDS_OPENAT2_E                                                          \
  (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_STRING_SIZE) +           \
   sizeof(uint64_t) * 3)

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
#define TDS_ACCEPT_E                                                           \
  (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_UNIX_SOCKET_PATH))

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
#define TDS_BIND_E                                                             \
  (TMD_SIZE + sizeof(int32_t) * 2 + (PARAM_SIZE + MAX_UNIX_SOCKET_PATH))

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
#define TDS_CONNECT_E                                                          \
  (TMD_SIZE + sizeof(int32_t) * 2 + MAX_UNIX_SOCKET_PATH + PARAM_SIZE)

/**
 * Connect exit
 * - metadata - 8701
 * - return value - 4
 * Total size: 8705 bytes
 */
#define TDS_CONNECT_R (TMD_SIZE + sizeof(int32_t))

/*************************** Event Data Size - END ***************************/

#endif