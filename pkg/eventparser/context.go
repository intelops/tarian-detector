// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package eventparser

// TarianMetaData represents the metadata associated with a event being received from the kernel.
// The first 755 bytes received from kernel in form of []byte are of type TarianMetaData
type TarianMetaData struct {
	MetaData struct {
		Event     int32    // Event identifier
		Nparams   uint8    // Number of parameters
		Syscall   int32    // System call i
		Ts        uint64   // Timestamp
		Processor uint16   // Processor number
		Task      struct { // Task information
			StartTime    uint64     // Start time
			HostPid      uint32     // Host process ID
			HostTgid     uint32     // Host thread group ID
			HostPpid     uint32     // Host parent process ID
			Pid          uint32     // Process ID of a namespace
			Tgid         uint32     // Thread group ID of a namespace
			Ppid         uint32     // Parent process ID of a namespace
			Uid          uint32     // User ID
			Gid          uint32     // Group ID
			CgroupId     uint64     // Cgroup ID
			MountNsId    uint64     // Mount namespace ID
			PidNsId      uint64     // Process namespace ID
			ExecId       uint64     // Execution ID
			ParentExecId uint64     // Parent execution ID
			Comm         [16]uint8  // Command
			Cwd          [256]uint8 // Current working directory
		}
	}
	SystemInfo struct {
		Sysname    [65]uint8 // System name
		Nodename   [65]uint8 // Node name
		Release    [65]uint8 // Release
		Version    [65]uint8 // Version
		Machine    [65]uint8 // Machine
		Domainname [65]uint8 // Domain name
	}
}

// TarianParamType represents the type of Tarian parameter
type TarianParamType uint32

const (
	TDT_NONE      TarianParamType = 0  // TDT_NONE represents the absence of a Tarian parameter
	TDT_U8        TarianParamType = 1  // TDT_U8 represents an 8-bit unsigned integer Tarian parameter
	TDT_U16       TarianParamType = 2  // TDT_U16 represents a 16-bit unsigned integer Tarian parameter
	TDT_U32       TarianParamType = 3  // TDT_U32 represents a 32-bit unsigned integer Tarian parameter
	TDT_U64       TarianParamType = 4  // TDT_U64 represents a 64-bit unsigned integer Tarian parameter
	TDT_S8        TarianParamType = 5  // TDT_S8 represents an 8-bit signed integer Tarian parameter
	TDT_S16       TarianParamType = 6  // TDT_S16 represents a 16-bit signed integer Tarian parameter
	TDT_S32       TarianParamType = 7  // TDT_S32 represents a 32-bit signed integer Tarian parameter
	TDT_S64       TarianParamType = 8  // TDT_S64 represents a 64-bit signed integer Tarian parameter
	TDT_IPV6      TarianParamType = 9  // TDT_IPV6 represents an IPv6 Tarian parameter
	TDT_STR       TarianParamType = 10 // TDT_STR represents a string Tarian parameter
	TDT_STR_ARR   TarianParamType = 11 // TDT_STR_ARR represents an array of strings Tarian parameter
	TDT_BYTE_ARR  TarianParamType = 12 // TDT_BYTE_ARR represents an array of bytes Tarian parameter
	TDT_IOVEC_ARR TarianParamType = 15 // TDT_IOVEC_ARR represents an array of I/O vectors Tarian parameter
	TDT_SOCKADDR  TarianParamType = 14 // TDT_SOCKADDR represents a socket address Tarian parameter
)

// TarianEventsE represents the type for Tarian events enumeration.
type TarianEventsE int

const (
	TDE_SYSCALL_EXECVE_E TarianEventsE = 2 // TDE_SYSCALL_EXECVE_E represents the start of an execve syscall
	TDE_SYSCALL_EXECVE_R TarianEventsE = 3 // TDE_SYSCALL_EXECVE_R represents the return of an execve syscall

	TDE_SYSCALL_EXECVEAT_E TarianEventsE = 4 // TDE_SYSCALL_EXECVEAT_E represents the start of an execveat syscall
	TDE_SYSCALL_EXECVEAT_R TarianEventsE = 5 // TDE_SYSCALL_EXECVEAT_R represents the return of an execveat syscall

	TDE_SYSCALL_CLONE_E TarianEventsE = 6 // TDE_SYSCALL_CLONE_E represents the start of a clone syscall
	TDE_SYSCALL_CLONE_R TarianEventsE = 7 // TDE_SYSCALL_CLONE_R represents the return of a clone syscall

	TDE_SYSCALL_CLOSE_E TarianEventsE = 8 // TDE_SYSCALL_CLOSE_E represents the start of a close syscall
	TDE_SYSCALL_CLOSE_R TarianEventsE = 9 // TDE_SYSCALL_CLOSE_R represents the return of a close syscall

	TDE_SYSCALL_READ_E TarianEventsE = 10 // TDE_SYSCALL_READ_E represents the start of a read syscall
	TDE_SYSCALL_READ_R TarianEventsE = 11 // TDE_SYSCALL_READ_R represents the return of a read syscall

	TDE_SYSCALL_WRITE_E TarianEventsE = 12 // TDE_SYSCALL_WRITE_E represents the start of a write syscall
	TDE_SYSCALL_WRITE_R TarianEventsE = 13 // TDE_SYSCALL_WRITE_R represents the return of a write syscall

	TDE_SYSCALL_OPEN_E TarianEventsE = 14 // TDE_SYSCALL_OPEN_E represents the start of an open syscall
	TDE_SYSCALL_OPEN_R TarianEventsE = 15 // TDE_SYSCALL_OPEN_R represents the return of an open syscall

	TDE_SYSCALL_READV_E TarianEventsE = 16 // TDE_SYSCALL_READV_E represents the start of a readv syscall
	TDE_SYSCALL_READV_R TarianEventsE = 17 // TDE_SYSCALL_READV_R represents the return of a readv syscall

	TDE_SYSCALL_WRITEV_E TarianEventsE = 18 // TDE_SYSCALL_WRITEV_E represents the start of a writev syscall
	TDE_SYSCALL_WRITEV_R TarianEventsE = 19 // TDE_SYSCALL_WRITEV_R represents the return of a writev syscall

	TDE_SYSCALL_OPENAT_E TarianEventsE = 20 // TDE_SYSCALL_OPENAT_E represents the start of an openat syscall
	TDE_SYSCALL_OPENAT_R TarianEventsE = 21 // TDE_SYSCALL_OPENAT_R represents the return of an openat syscall

	TDE_SYSCALL_OPENAT2_E TarianEventsE = 22 // TDE_SYSCALL_OPENAT2_E represents the start of an openat2 syscall
	TDE_SYSCALL_OPENAT2_R TarianEventsE = 23 // TDE_SYSCALL_OPENAT2_R represents the return of an openat2 syscall

	TDE_SYSCALL_LISTEN_E TarianEventsE = 24 // TDE_SYSCALL_LISTEN_E represents the start of a listen syscall
	TDE_SYSCALL_LISTEN_R TarianEventsE = 25 // TDE_SYSCALL_LISTEN_R represents the return of a listen syscall

	TDE_SYSCALL_SOCKET_E TarianEventsE = 26 // TDE_SYSCALL_SOCKET_E represents the start of a socket syscall
	TDE_SYSCALL_SOCKET_R TarianEventsE = 27 // TDE_SYSCALL_SOCKET_R represents the return of a socket syscall

	TDE_SYSCALL_ACCEPT_E TarianEventsE = 28 // TDE_SYSCALL_ACCEPT_E represents the start of an accept syscall
	TDE_SYSCALL_ACCEPT_R TarianEventsE = 29 // TDE_SYSCALL_ACCEPT_R represents the return of an accept syscall

	TDE_SYSCALL_BIND_E TarianEventsE = 30 // TDE_SYSCALL_BIND_E represents the start of a bind syscall
	TDE_SYSCALL_BIND_R TarianEventsE = 31 // TDE_SYSCALL_BIND_R represents the return of a bind syscall

	TDE_SYSCALL_CONNECT_E TarianEventsE = 32 // TDE_SYSCALL_CONNECT_E represents the start of a connect syscall
	TDE_SYSCALL_CONNECT_R TarianEventsE = 33 // TDE_SYSCALL_CONNECT_R represents the return of a connect syscall
)
