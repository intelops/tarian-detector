#ifndef __UTLIS_SHARED_CONSTANTS_H__
#define __UTLIS_SHARED_CONSTANTS_H__

#define MAX_PATH_LOOP 20
#define MAX_NODE_FIELD_SIZE 65    /* 65B */
#define MAX_STRING_SIZE 4096   
#define MAX_TARIAN_PATH 256   
#define MAX_SCRATCH_SPACE 8192
#define MAX_BUFFER_SIZE 1024 * 128    /* 128kB */
#define MAX_EVENT_SIZE 64 * 1024    /* 64kB */

#define TASK_COMM_LEN 16

#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE KERNEL_VERSION(LINUX_VERSION_MAJOR, LINUX_VERSION_MINOR, LINUX_VERSION_PATCH)
#endif

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10

#define EVENT_RINGBUF_MAP_NAME events
#define RINGBUF_MAX_ENTRIES 1024 * 1024 * 128 /* 128MB */
#define ARRAY_OF_MAPS_MAX_ENTRIES 16

#define stain static __always_inline

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 2, 0))
#define MAX_NUM_COMPONENTS 48
#else
#define MAX_NUM_COMPONENTS 24
#endif

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
    TDT_IOVEC_ARR,
    TDT_SOCKADDR,
};  
typedef enum tarian_events_e{
    // execve
    TDE_SYSCALL_EXECVE_E = 2,
    TDE_SYSCALL_EXECVE_R,

    // execveat
    TDE_SYSCALL_EXECVEAT_E,
    TDE_SYSCALL_EXECVEAT_R,
    
    // clone
    TDE_SYSCALL_CLONE_E,
    TDE_SYSCALL_CLONE_R,

    // close
    TDE_SYSCALL_CLOSE_E,
    TDE_SYSCALL_CLOSE_R,

    // read
    TDE_SYSCALL_READ_E,
    TDE_SYSCALL_READ_R,

    // write
    TDE_SYSCALL_WRITE_E,
    TDE_SYSCALL_WRITE_R,

    // open
    TDE_SYSCALL_OPEN_E,
    TDE_SYSCALL_OPEN_R,

    // readv
    TDE_SYSCALL_READV_E,
    TDE_SYSCALL_READV_R,

    // writev
    TDE_SYSCALL_WRITEV_E,
    TDE_SYSCALL_WRITEV_R,

    // openat
    TDE_SYSCALL_OPENAT_E,
    TDE_SYSCALL_OPENAT_R,

    // openat2
    TDE_SYSCALL_OPENAT2_E,
    TDE_SYSCALL_OPENAT2_R,
    
    // listen
    TDE_SYSCALL_LISTEN_E,
    TDE_SYSCALL_LISTEN_R,

    // socket
    TDE_SYSCALL_SOCKET_E,
    TDE_SYSCALL_SOCKET_R,

    // accept
    TDE_SYSCALL_ACCEPT_E,
    TDE_SYSCALL_ACCEPT_R,

    // bind
    TDE_SYSCALL_BIND_E,
    TDE_SYSCALL_BIND_R,

    // connect
    TDE_SYSCALL_CONNECT_E,
    TDE_SYSCALL_CONNECT_R,
} tarian_event_code;

/*****Event Data Size - START****/
#define MD_SIZE sizeof(tarian_meta_data_t) /* sizeof tarian meta data for each event*/
#define PARAM_SIZE sizeof(uint16_t)

#define TDS_EXECVE_E (MD_SIZE + MAX_STRING_SIZE*2 + PARAM_SIZE*2)
#define TDS_EXECVE_R (MD_SIZE + sizeof(int32_t))

#define TDS_EXECVEAT_E (MD_SIZE + sizeof(int32_t)*2 + MAX_STRING_SIZE*2 + PARAM_SIZE*2)
#define TDS_EXECVEAT_R (MD_SIZE + sizeof(int32_t))

#define TDS_CLONE_E (MD_SIZE + sizeof(uint64_t)*3 + sizeof(int32_t)*2)
#define TDS_CLONE_R (MD_SIZE + sizeof(int32_t))

#define TDS_CLOSE_E (MD_SIZE + sizeof(int32_t))
#define TDS_CLOSE_R (MD_SIZE + sizeof(int32_t))

#define TDS_READ_E (MD_SIZE + sizeof(int32_t) + MAX_STRING_SIZE + PARAM_SIZE + sizeof(uint32_t))
#define TDS_READ_R (MD_SIZE + sizeof(long))

#define TDS_WRITE_E (MD_SIZE + sizeof(int32_t) + MAX_STRING_SIZE + PARAM_SIZE + sizeof(uint32_t))
#define TDS_WRITE_R (MD_SIZE + sizeof(long))

#define TDS_OPEN_E (MD_SIZE + MAX_STRING_SIZE + PARAM_SIZE + sizeof(int32_t) + sizeof(uint32_t))
#define TDS_OPEN_R (MD_SIZE + sizeof(int32_t))

#define TDS_READV_E (MD_SIZE + sizeof(int32_t) * 2 + MAX_STRING_SIZE + PARAM_SIZE)
#define TDS_READV_R (MD_SIZE + sizeof(long))

#define TDS_WRITEV_E (MD_SIZE + sizeof(int32_t) * 2 + MAX_STRING_SIZE + PARAM_SIZE)
#define TDS_WRITEV_R (MD_SIZE + sizeof(long))

#define TDS_OPENAT_E (MD_SIZE + sizeof(int32_t) * 2 + MAX_STRING_SIZE + PARAM_SIZE + sizeof(uint32_t))
#define TDS_OPENAT_R (MD_SIZE + sizeof(int32_t))

#define TDS_OPENAT2_E (MD_SIZE + sizeof(int32_t) * 2 + MAX_STRING_SIZE + PARAM_SIZE + sizeof(uint64_t) * 3)
#define TDS_OPENAT2_R (MD_SIZE + sizeof(long))

#define TDS_LISTEN_E (MD_SIZE + sizeof(int32_t) * 2)
#define TDS_LISTEN_R (MD_SIZE + sizeof(int32_t))

#define TDS_SOCKET_E (MD_SIZE + sizeof(int32_t) * 3)
#define TDS_SOCKET_R (MD_SIZE + sizeof(int32_t))

#define TDS_ACCEPT_E (MD_SIZE + sizeof(int32_t) * 2 + MAX_UNIX_SOCKET_PATH + PARAM_SIZE)
#define TDS_ACCEPT_R (MD_SIZE + sizeof(int32_t))

#define TDS_BIND_E (MD_SIZE + sizeof(int32_t) * 2 +  MAX_UNIX_SOCKET_PATH + PARAM_SIZE)
#define TDS_BIND_R (MD_SIZE + sizeof(int32_t))

#define TDS_CONNECT_E (MD_SIZE + sizeof(int32_t) * 2 +  MAX_UNIX_SOCKET_PATH + PARAM_SIZE)
#define TDS_CONNECT_R (MD_SIZE + sizeof(int32_t))
/*****Event Data Size - END*****/

#endif