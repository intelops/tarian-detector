// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"fmt"
	"strings"

	"github.com/intelops/tarian-detector/pkg/err"
)

var transformErr = err.New("eventparser.transform")

const (
	AT_FDCWD              = -100   // Special value indicating the *at functions should use the current working directory.
	AT_SYMLINK_FOLLOW     = 0x400  // Follow symbolic links.
	AT_SYMLINK_NOFOLLOW   = 0x100  // Do not follow symbolic links.
	AT_REMOVEDIR          = 0x200  // Remove directory instead of unlinking file.
	AT_NO_AUTOMOUNT       = 0x800  // Suppress terminal automount traversal.
	AT_EMPTY_PATH         = 0x1000 // Used for an empty pathname.
	AT_STATX_SYNC_TYPE    = 0x6000 // Synchronization type for querying file attributes.
	AT_STATX_SYNC_AS_STAT = 0x0000 // Synchronize as stat (default behavior).
	AT_STATX_FORCE_SYNC   = 0x2000 // Force synchronization.
	AT_STATX_DONT_SYNC    = 0x4000 // Do not synchronize.
	AT_RECURSIVE          = 0x8000 // Recursive behavior.
	AT_EACCESS            = 0x200  // Test access permitted for effective IDs, not real IDs.
)

var execveatDird = map[int32]string{
	AT_FDCWD:      "AT_FDCWD",      // Special value for current working directory
	AT_EMPTY_PATH: "AT_EMPTY_PATH", // Empty pathname
}

// parseExecveatDird parses the provided value and returns a descriptive string
// corresponding to the given integer constant.
func parseExecveatDird(dird any) (string, error) {
	d, ok := dird.(int32)
	if !ok {
		return fmt.Sprintf("%v", dird), transformErr.Throwf("parseExecveatDird: parse value error expected %T received %T", d, dird)
	}

	if s, ok := execveatDird[d]; ok {
		return s, nil
	}

	return fmt.Sprintf("%v", d), nil
}

// Use a slice to store the flags that need to be checked
var execveatFlag = []struct {
	flag int32
	name string
}{
	{AT_EMPTY_PATH, "AT_EMPTY_PATH"},             // Flag for an empty pathname
	{AT_SYMLINK_NOFOLLOW, "AT_SYMLINK_NOFOLLOW"}, // Avoid following symbolic links
}

// parseExecveatFlags parses the given flag value and returns a string representation
// of the corresponding flags based on the execveatFlag definitions.
func parseExecveatFlags(flag any) (string, error) {
	f, ok := flag.(int32)
	if !ok {
		return fmt.Sprintf("%v", flag), transformErr.Throwf("parseExecveatFlags: parse value error expected %T received %T", f, flag)
	}

	var fs []string
	for _, v := range execveatFlag {
		if f&v.flag == v.flag {
			fs = append(fs, v.name)
		}
	}

	if len(fs) == 0 {
		return fmt.Sprintf("%v", flag), nil
	}

	return strings.Join(fs, "|"), nil
}

// Constants representing various clone flags used in system calls.
const (
	CSIGNAL              = 0x000000ff // Signal mask to be sent at exit.
	CLONE_VM             = 0x00000100 // Share memory space with the parent process.
	CLONE_FS             = 0x00000200 // Share filesystem information.
	CLONE_FILES          = 0x00000400 // Share file descriptors.
	CLONE_SIGHAND        = 0x00000800 // Share signal handlers.
	CLONE_PIDFD          = 0x00001000 // Use pidfd instead of child's PID.
	CLONE_PTRACE         = 0x00002000 // Allow tracing of child processes.
	CLONE_VFORK          = 0x00004000 // Create a new process but share memory until exec.
	CLONE_PARENT         = 0x00008000 // Set parent process ID to the calling process.
	CLONE_THREAD         = 0x00010000 // Create a thread (shared memory, signal handlers, etc.).
	CLONE_NEWNS          = 0x00020000 // Create a new mount namespace.
	CLONE_SYSVSEM        = 0x00040000 // Share System V semaphores.
	CLONE_SETTLS         = 0x00080000 // Set TLS (Thread-Local Storage) for the child.
	CLONE_PARENT_SETTID  = 0x00100000 // Set the parent's TID (Thread ID).
	CLONE_CHILD_CLEARTID = 0x00200000 // Clear the TID in the child.
	CLONE_DETACHED       = 0x00400000 // Create a detached thread.
	CLONE_UNTRACED       = 0x00800000 // Do not report the child's status to the parent.
	CLONE_CHILD_SETTID   = 0x01000000 // Set the child's TID.
	CLONE_NEWCGROUP      = 0x02000000 // Create a new cgroup namespace.
	CLONE_NEWUTS         = 0x04000000 // Create a new UTS (hostname) namespace.
	CLONE_NEWIPC         = 0x08000000 // Create a new IPC namespace.
	CLONE_NEWUSER        = 0x10000000 // Create a new user namespace.
	CLONE_NEWPID         = 0x20000000 // Create a new PID namespace.
	CLONE_NEWNET         = 0x40000000 // Create a new network namespace.
	CLONE_IO             = 0x80000000 // Clone I/O context.
)

// cloneFlags represents various clone flags used in system calls.
var cloneFlags = map[uint64]string{
	CSIGNAL:              "CSIGNAL",
	CLONE_VM:             "CLONE_VM",
	CLONE_FS:             "CLONE_FS",
	CLONE_FILES:          "CLONE_FILES",
	CLONE_SIGHAND:        "CLONE_SIGHAND",
	CLONE_PIDFD:          "CLONE_PIDFD",
	CLONE_PTRACE:         "CLONE_PTRACE",
	CLONE_VFORK:          "CLONE_VFORK",
	CLONE_PARENT:         "CLONE_PARENT",
	CLONE_THREAD:         "CLONE_THREAD",
	CLONE_NEWNS:          "CLONE_NEWNS",
	CLONE_SYSVSEM:        "CLONE_SYSVSEM",
	CLONE_SETTLS:         "CLONE_SETTLS",
	CLONE_PARENT_SETTID:  "CLONE_PARENT_SETTID",
	CLONE_CHILD_CLEARTID: "CLONE_CHILD_CLEARTID",
	CLONE_DETACHED:       "CLONE_DETACHED",
	CLONE_UNTRACED:       "CLONE_UNTRACED",
	CLONE_CHILD_SETTID:   "CLONE_CHILD_SETTID",
	CLONE_NEWCGROUP:      "CLONE_NEWCGROUP",
	CLONE_NEWUTS:         "CLONE_NEWUTS",
	CLONE_NEWIPC:         "CLONE_NEWIPC",
	CLONE_NEWUSER:        "CLONE_NEWUSER",
	CLONE_NEWPID:         "CLONE_NEWPID",
	CLONE_NEWNET:         "CLONE_NEWNET",
	CLONE_IO:             "CLONE_IO",
}

// parseCloneFlags parses the given flag value and returns a string representation
// of the corresponding flags based on the cloneFlags definitions.
func parseCloneFlags(flag any) (string, error) {
	f, ok := flag.(uint64)
	if !ok {
		return fmt.Sprintf("%v", flag), transformErr.Throwf("parseCloneFlags: parse value error expected %T received %T", f, flag)
	}

	var fs []string
	for key, name := range cloneFlags {
		if f&key == key {
			f -= key
			fs = append(fs, name)
		}
	}

	if f > 0 {
		sigs := parseSignal(uint16(f))

		fs = append(fs, sigs)
	}

	if len(fs) == 0 {
		return fmt.Sprintf("%v", f), nil
	}

	return strings.Join(fs, "|"), nil
}

// signalMap represents various signal numbers and their corresponding names.
var signalMap = map[uint16]string{
	1:  "SIGHUP",    // Hangup (terminal line disconnected).
	2:  "SIGINT",    // Interrupt (Ctrl+C).
	3:  "SIGQUIT",   // Quit (Ctrl+\).
	4:  "SIGILL",    // Illegal instruction.
	5:  "SIGTRAP",   // Trace/breakpoint trap.
	6:  "SIGABRT",   // Aborted.
	7:  "SIGBUS",    // Bus error.
	8:  "SIGFPE",    // Floating-point exception.
	9:  "SIGKILL",   // Killed (cannot be caught or ignored).
	10: "SIGUSR1",   // User-defined signal 1.
	11: "SIGSEGV",   // Segmentation fault.
	12: "SIGUSR2",   // User-defined signal 2.
	13: "SIGPIPE",   // Broken pipe.
	14: "SIGALRM",   // Alarm clock.
	15: "SIGTERM",   // Termination (software termination signal).
	16: "SIGSTKFLT", // Stack fault.
	17: "SIGCHLD",   // Child process terminated or stopped.
	18: "SIGCONT",   // Continue executing if stopped.
	19: "SIGSTOP",   // Stop executing (cannot be caught or ignored).
	20: "SIGTSTP",   // Terminal stop signal (Ctrl+Z).
	21: "SIGTTIN",   // Background process attempting read from terminal.
	22: "SIGTTOU",   // Background process attempting write to terminal.
	23: "SIGURG",    // Urgent data is available on a socket.
	24: "SIGXCPU",   // CPU time limit exceeded.
	25: "SIGXFSZ",   // File size limit exceeded.
	26: "SIGVTALRM", // Virtual timer expired.
	27: "SIGPROF",   // Profiling timer expired.
	28: "SIGWINCH",  // Window size change.
	29: "SIGIO",     // I/O now possible (e.g., socket ready for reading/writing).
	30: "SIGPWR",    // Power failure or restart.
	31: "SIGSYS",    // Bad system call.
}

// parseSignal takes a signal number (sig) and returns its corresponding name.
func parseSignal(sig uint16) string {
	name, ok := signalMap[sig]
	if !ok {
		return fmt.Sprintf("%v", sig)
	}

	return name
}

// parseOpenMode takes an open mode value (mode) and returns its octal representation.
func parseOpenMode(mode any) (string, error) {
	m, ok := mode.(uint32)
	if !ok {
		return fmt.Sprintf("%v", mode), transformErr.Throwf("parseOpenMode: parse value error expected %T received %T", m, mode)
	}

	return fmt.Sprintf("%04o", m), nil
}

// Constants representing various file open modes.
const (
	O_ACCMODE   = 0003      // Mask for access mode (read, write, execute).
	O_RDONLY    = 00        // Open for read-only.
	O_WRONLY    = 01        // Open for write-only.
	O_RDWR      = 02        // Open for read-write.
	O_CREAT     = 0100      // Create the file if it does not exist.
	O_EXCL      = 0200      // Exclusive use: fail if file already exists.
	O_NOCTTY    = 0400      // Do not make the file a controlling terminal.
	O_TRUNC     = 01000     // Truncate the file if it already exists.
	O_APPEND    = 02000     // Append data to the file.
	O_NONBLOCK  = 04000     // Non-blocking mode.
	O_SYNC      = 04010000  // Synchronize data on file write.
	O_ASYNC     = 020000    // Enable asynchronous I/O.
	O_LARGEFILE = 0100000   // Enable large file support.
	O_DIRECTORY = 0200000   // Fail if not a directory.
	O_NOFOLLOW  = 0400000   // Do not follow symbolic links.
	O_CLOEXEC   = 02000000  // Close the file descriptor upon exec.
	O_DIRECT    = 040000    // Direct I/O flag.
	O_NOATIME   = 01000000  // Do not update file access time.
	O_PATH      = 010000000 // Open directory without following symlinks.
	O_DSYNC     = 010000    // Synchronize data on file write, but not metadata.
	O_TMPFILE   = 020000000 // Create an unnamed temporary file.
)

// openFlags represents various file open flags.
var openFlags = map[int32]string{
	O_ACCMODE:   "O_ACCMODE",
	O_CREAT:     "O_CREAT",
	O_EXCL:      "O_EXCL",
	O_NOCTTY:    "O_NOCTTY",
	O_TRUNC:     "O_TRUNC",
	O_APPEND:    "O_APPEND",
	O_NONBLOCK:  "O_NONBLOCK",
	O_SYNC:      "O_SYNC",
	O_ASYNC:     "O_ASYNC",
	O_LARGEFILE: "O_LARGEFILE",
	O_DIRECTORY: "O_DIRECTORY",
	O_NOFOLLOW:  "O_NOFOLLOW",
	O_CLOEXEC:   "O_CLOEXEC",
	O_DIRECT:    "O_DIRECT",
	O_NOATIME:   "O_NOATIME",
	O_PATH:      "O_PATH",
	O_DSYNC:     "O_DSYNC",
	O_TMPFILE:   "O_TMPFILE",
}

// parseOpenFlags takes an open flags value (flags) and returns a string representation
// of the corresponding flags based on the openFlags definitions.
func parseOpenFlags(flags any) (string, error) {
	f, ok := flags.(int32)
	if !ok {
		return fmt.Sprintf("%v", flags), transformErr.Throwf("parseOpenFlags: parse value error expected %T received %T", f, flags)
	}

	var fs []string

	if f&O_WRONLY == O_WRONLY {
		fs = append(fs, "O_WRONLY")
	} else if f&O_RDWR == O_RDWR {
		fs = append(fs, "O_RDWR")
	} else {
		fs = append(fs, "O_RDONLY")
	}

	for flag, name := range openFlags {
		if f&flag == flag {
			fs = append(fs, name)
		}
	}

	return strings.Join(fs, "|"), nil
}

// parseOpenat2Flags takes an openat2 flags value (flags) and returns a string representation
// of the corresponding flags based on the openFlags definitions.
func parseOpenat2Flags(flags any) (string, error) {
	f, ok := flags.(int64)
	if !ok {
		return fmt.Sprintf("%v", flags), transformErr.Throwf("parseOpenat2Flags: parse value error expected %T received %T", f, flags)
	}

	return parseOpenFlags(int32(f))
}

// parseOpenat2Mode takes an openat2 mode value (mode) and returns its octal representation.
func parseOpenat2Mode(mode any) (string, error) {
	m, ok := mode.(int64)
	if !ok {
		return fmt.Sprintf("%v", mode), transformErr.Throwf("parseOpenat2Mode: parse value error expected %T received %T", m, mode)
	}

	return parseOpenMode(uint32(m))
}

// Constants representing various options for file path resolution.
const (
	RESOLVE_NO_XDEV       = 0x01 // Do not cross mount points (stay within the same filesystem).
	RESOLVE_NO_MAGICLINKS = 0x02 // Do not follow magic links (e.g., /proc/self/exe).
	RESOLVE_NO_SYMLINKS   = 0x04 // Do not follow symbolic links.
	RESOLVE_BENEATH       = 0x08 // Resolve paths only if they are beneath the specified directory.
	RESOLVE_IN_ROOT       = 0x10 // Resolve paths relative to the root directory.
	RESOLVE_CACHED        = 0x20 // Use cached information for resolution.
)

// openat2ResolveFlags represents various options for file path resolution in the openat2 system call.
var openat2ResolveFlags = map[int64]string{
	RESOLVE_NO_XDEV:       "RESOLVE_NO_XDEV",
	RESOLVE_NO_MAGICLINKS: "RESOLVE_NO_MAGICLINKS",
	RESOLVE_NO_SYMLINKS:   "RESOLVE_NO_SYMLINKS",
	RESOLVE_BENEATH:       "RESOLVE_BENEATH",
	RESOLVE_IN_ROOT:       "RESOLVE_IN_ROOT",
	RESOLVE_CACHED:        "RESOLVE_CACHED",
}

// parseOpenat2Resolve takes an openat2 resolve value (resolve) and returns a string representation
// of the corresponding flags based on the openat2ResolveFlags definitions.
func parseOpenat2Resolve(resovle any) (string, error) {
	r, ok := resovle.(int64)
	if !ok {
		return fmt.Sprintf("%v", resovle), transformErr.Throwf("parseOpenat2Resolve: parse value error expected %T received %T", r, resovle)
	}

	var rs []string
	for resolve, name := range openat2ResolveFlags {
		if r&resolve == resolve {
			rs = append(rs, name)
		}
	}

	if len(rs) == 0 {
		return fmt.Sprintf("%v", r), nil
	}

	return strings.Join(rs, "|"), nil
}

// Constants representing address families in networking.
const (
	AF_UNIX  = 1  // Unix domain sockets (local communication).
	AF_INET  = 2  // IPv4 addresses.
	AF_INET6 = 10 // IPv6 addresses.
)

// socketFamilyNames represents various address families used in networking.
var socketFamilyNames = map[int32]string{
	0:  "AF_UNSPEC",     // Unspecified address family.
	1:  "AF_UNIX",       // Unix domain sockets (local communication).
	2:  "AF_INET",       // IPv4 addresses.
	3:  "AF_AX25",       // AX.25 amateur radio protocol.
	4:  "AF_IPX",        // IPX/SPX protocol.
	5:  "AF_APPLETALK",  // AppleTalk protocol.
	6:  "AF_NETROM",     // Amateur radio NET/ROM protocol.
	7:  "AF_BRIDGE",     // Ethernet bridging.
	8:  "AF_ATMPVC",     // ATM PVCs.
	9:  "AF_X25",        // X.25 protocol.
	10: "AF_INET6",      // IPv6 addresses.
	11: "AF_ROSE",       // Amateur Radio X.25 PLP protocol.
	12: "AF_DECnet",     // DECnet protocol.
	13: "AF_NETBEUI",    // NetBIOS over IEEE 802.2.
	14: "AF_SECURITY",   // Security callback pseudo AF.
	15: "AF_KEY",        // PF_KEY key management API.
	16: "AF_NETLINK",    // Netlink sockets.
	17: "AF_PACKET",     // Low-level packet interface.
	18: "AF_ASH",        // Ash.
	19: "AF_ECONET",     // Acorn Econet.
	20: "AF_ATMSVC",     // ATM SVCs.
	21: "AF_RDS",        // Reliable Datagram Sockets.
	22: "AF_SNA",        // Linux SNA Project.
	23: "AF_IRDA",       // IRDA sockets.
	24: "AF_PPPOX",      // PPPoX sockets.
	25: "AF_WANPIPE",    // Wanpipe API sockets.
	26: "AF_LLC",        // Linux LLC.
	27: "AF_IB",         // InfiniBand.
	28: "AF_MPLS",       // MPLS.
	29: "AF_CAN",        // Controller Area Network.
	30: "AF_TIPC",       // TIPC sockets.
	31: "AF_BLUETOOTH",  // Bluetooth sockets.
	32: "AF_IUCV",       // IUCV sockets.
	33: "AF_RXRPC",      // RxRPC sockets.
	34: "AF_ISDN",       // ISDN sockets.
	35: "AF_PHONET",     // Phonet sockets.
	36: "AF_IEEE802154", // IEEE 802.15.4 sockets.
	37: "AF_CAIF",       // CAIF sockets.
	38: "AF_ALG",        // Algorithm sockets.
	39: "AF_NFC",        // NFC sockets.
	40: "AF_VSOCK",      // vSockets.
	41: "AF_KCM",        // Kernel Connection Multiplexor.
	42: "AF_QIPCRTR",    // Quick IPC router.
	43: "AF_SMC",        // SMC (System Management Controller) protocol.
	44: "AF_XDP",        // XDP (eXpress Data Path) sockets.
}

// parseSocketFamily takes a socket family value (n) and returns its corresponding name.
func parseSocketFamily(family any) (string, error) {
	f, ok := family.(int32)
	if !ok {
		return fmt.Sprintf("%v", family), transformErr.Throwf("parseSocketFamily: parse value error expected %T received %T", f, family)
	}

	if name, ok := socketFamilyNames[f]; ok {
		return name, nil
	}

	return fmt.Sprintf("%v", f), nil
}

// socketTypes represents various socket types.
var socketTypes = map[int32]string{
	1:  "SOCK_STREAM",    // Provides reliable, stream-oriented communication (e.g., TCP).
	2:  "SOCK_DGRAM",     // Provides unreliable, datagram-oriented communication (e.g., UDP).
	3:  "SOCK_RAW",       // Provides raw network protocol access.
	4:  "SOCK_RDM",       // Provides reliable datagram communication.
	5:  "SOCK_SEQPACKET", // Provides reliable, sequenced packet communication.
	6:  "SOCK_DCCP",      // Datagram Congestion Control Protocol.
	10: "SOCK_PACKET",    // Low-level packet interface.
}

// Constants representing socket options.
const (
	SOCK_CLOEXEC  = 02000000 // Close the socket descriptor upon exec.
	SOCK_NONBLOCK = 00004000 // Enable non-blocking mode for the socket.
)

// parseSocketType takes a socket type value (n) and returns its corresponding name.
func parseSocketType(typ any) (string, error) {
	t, ok := typ.(int32)
	if !ok {
		return fmt.Sprintf("%v", typ), transformErr.Throwf("parseSocketType: parse value error expected %T received %T", t, typ)
	}

	var ts []string
	if tp, ok := socketTypes[t&0xf]; ok {
		ts = append(ts, tp)
	} else {
		ts = append(ts, fmt.Sprintf("%v", t))
	}

	if t&SOCK_CLOEXEC == SOCK_CLOEXEC {
		ts = append(ts, "SOCK_CLOEXEC")
	}

	if t&SOCK_NONBLOCK == SOCK_NONBLOCK {
		ts = append(ts, "SOCK_NONBLOCK")
	}

	return strings.Join(ts, "|"), nil
}

// socketProtocols represents various IP protocols used in networking.
var socketProtocols = map[int32]string{
	0:   "IPPROTO_IP",      // Internet Protocol (IP).
	1:   "IPPROTO_ICMP",    // Internet Control Message Protocol (ICMP).
	2:   "IPPROTO_IGMP",    // Internet Group Management Protocol (IGMP).
	4:   "IPPROTO_IPIP",    // IP in IP encapsulation.
	6:   "IPPROTO_TCP",     // Transmission Control Protocol (TCP).
	8:   "IPPROTO_EGP",     // Exterior Gateway Protocol (EGP).
	12:  "IPPROTO_PUP",     // PARC Universal Packet Protocol (PUP).
	17:  "IPPROTO_UDP",     // User Datagram Protocol (UDP).
	22:  "IPPROTO_IDP",     // Xerox NS IDP.
	29:  "IPPROTO_TP",      // ISO Transport Protocol Class 4 (TP).
	33:  "IPPROTO_DCCP",    // Datagram Congestion Control Protocol (DCCP).
	41:  "IPPROTO_IPV6",    // IPv6 header.
	46:  "IPPROTO_RSVP",    // Resource Reservation Protocol (RSVP).
	47:  "IPPROTO_GRE",     // Generic Routing Encapsulation (GRE).
	50:  "IPPROTO_ESP",     // Encapsulating Security Payload (ESP).
	51:  "IPPROTO_AH",      // Authentication Header (AH).
	92:  "IPPROTO_MTP",     // Multicast Transport Protocol (MTP).
	94:  "IPPROTO_BEETPH",  // BEET PH Protocol.
	98:  "IPPROTO_ENCAP",   // Encapsulation Header (ENCAP).
	103: "IPPROTO_PIM",     // Protocol Independent Multicast (PIM).
	108: "IPPROTO_COMP",    // Compression Header Protocol.
	132: "IPPROTO_SCTP",    // Stream Control Transmission Protocol (SCTP).
	136: "IPPROTO_UDPLITE", // UDP-Lite.
	137: "IPPROTO_MPLS",    // MPLS in IP.
	255: "IPPROTO_RAW",     // Raw IP packets.
}

// parseSocketProtocol takes a socket protocol value (n) and returns its corresponding name.
func parseSocketProtocol(protocol any) (string, error) {
	p, ok := protocol.(int32)
	if !ok {
		return fmt.Sprintf("%v", protocol), transformErr.Throwf("parseSocketProtocol: parse value error expected %T received %T", p, protocol)
	}

	if prot, ok := socketProtocols[p]; ok {
		return prot, nil
	}

	return fmt.Sprintf("%v", p), nil
}
