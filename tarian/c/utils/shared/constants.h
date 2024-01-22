#ifndef __UTLIS_SHARED_CONSTANTS_H
#define __UTLIS_SHARED_CONSTANTS_H

#define MAX_ARGS 8
#define MAX_PATH_LOOP 20
#define MAX_STR_ARR_ELEM 38
#define MAX_NODE_FIELD_SIZE 65    /* 65B */
#define MAX_STRING_SIZE 4096      /* 4KB */
#define SYS_BUF_SIZE 1024 * 10
#define MAX_BUFFER_SIZE 1024 * 128    /* 128kB */
#define MAX_EVENT_SIZE 64 * 1024    /* 64kB */
#define MAX_PERCPU_BUFSIZE (1 << 15 /* 32768 */) // set by the kernel as an upper bound

#define TASK_COMM_LEN 16

#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE KERNEL_VERSION(LINUX_VERSION_MAJOR, LINUX_VERSION_MINOR, LINUX_VERSION_PATCH)
#endif

#define AF_INET 2
#define AF_INET6 10
#define AF_UNIX 1

#define EVENT_RINGBUF_MAP_NAME events
#define RINGBUF_MAX_ENTRIES 1024 * 1024 * 16 /* 16MB */
#define ARRAY_OF_MAPS_MAX_ENTRIES 16

#define stain static __always_inline

enum pt_regs_idx_e{
    PARAM1 = 0,
    PARAM2,
    PARAM3,
    PARAM4,
    PARAM5,
    PARAM6,
    SYSCALL,
    RETURN
};

enum argument_type_e {
    NONE_T = 0UL,
    INT_T,
    UINT_T,
    LONG_T,
    ULONG_T,
    STR_T,
    STR_ARR_T,
    BYTE_ARR_T,
    ARG_TYPE_MAX = 255UL
};

enum tarian_param_type_e{
    TDT_NONE = 0,
    TDT_U8,
    TDT_U16,
    TDT_U32,
    TDT_U64,
    TDT_S8,
    TDT_S16,
    TDT_S32,
    TDT_S64,
    TDT_IPV6,
    TDT_STR,
    TDT_STR_ARR,
    TDT_BYTE_ARR,
};  
typedef enum tarian_events_e{
    TDE_SYSCALL_EXECVE_E = 2,
    TDE_SYSCALL_EXECVE_R = 3
} tarian_event_code;

enum event_id_e {
    SYS_EXECVE_E = 0UL,
    SYS_EXECVE_X,
    SYS_ENTER_EXECVEAT,
    SYS_EXIT_EXECVEAT,
    SYS_ENTER_OPEN,
    SYS_EXIT_OPEN,
    SYS_ENTER_OPENAT,
    SYS_EXIT_OPENAT,
    SYS_ENTER_OPENAT2,
    SYS_EXIT_OPENAT2,
    SYS_ENTER_CLOSE,
    SYS_EXIT_CLOSE,
    SYS_ENTER_READ,
    SYS_EXIT_READ,
    SYS_ENTER_READV,
    SYS_EXIT_READV,
    SYS_ENTER_WRITE,
    SYS_EXIT_WRITE,
    SYS_ENTER_WRITEV,
    SYS_EXIT_WRITEV,
    SYS_ENTER_LISTEN,
    SYS_EXIT_LISTEN,
    SYS_ENTER_SOCKET,
    SYS_EXIT_SOCKET,
    SYS_ENTER_ACCEPT,
    SYS_EXIT_ACCEPT,
    SYS_ENTER_BIND,
    SYS_EXIT_BIND,
    SYS_ENTER_CONNECT,
    SYS_EXIT_CONNECT,
    SYS_ENTER_CLONE,
    SYS_EXIT_CLONE
};


/*****Event Data Size - START****/
#define MD_SIZE sizeof(tarian_meta_data_t) /* sizeof tarian meta data for each event*/
#define PARAM_SIZE sizeof(u16)

#define TDS_EXECVE_E (MD_SIZE + MAX_STRING_SIZE*2 + PARAM_SIZE*2)
#define TDS_EXECVE_R (MD_SIZE + sizeof(int))

/*****Event Data Size - END*****/

#endif