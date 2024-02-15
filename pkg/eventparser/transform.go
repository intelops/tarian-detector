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
	AT_FDCWD              = -100
	AT_SYMLINK_FOLLOW     = 0x400
	AT_SYMLINK_NOFOLLOW   = 0x100
	AT_REMOVEDIR          = 0x200
	AT_NO_AUTOMOUNT       = 0x800
	AT_EMPTY_PATH         = 0x1000
	AT_STATX_SYNC_TYPE    = 0x6000
	AT_STATX_SYNC_AS_STAT = 0x0000
	AT_STATX_FORCE_SYNC   = 0x2000
	AT_STATX_DONT_SYNC    = 0x4000
	AT_RECURSIVE          = 0x8000
	AT_EACCESS            = 0x200
)

var execveatDird = map[int32]string{
	AT_FDCWD:      "AT_FDCWD",
	AT_EMPTY_PATH: "AT_EMPTY_PATH",
}

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
	{AT_EMPTY_PATH, "AT_EMPTY_PATH"},
	{AT_SYMLINK_NOFOLLOW, "AT_SYMLINK_NOFOLLOW"},
}

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

const (
	CSIGNAL              = 0x000000ff
	CLONE_VM             = 0x00000100
	CLONE_FS             = 0x00000200
	CLONE_FILES          = 0x00000400
	CLONE_SIGHAND        = 0x00000800
	CLONE_PIDFD          = 0x00001000
	CLONE_PTRACE         = 0x00002000
	CLONE_VFORK          = 0x00004000
	CLONE_PARENT         = 0x00008000
	CLONE_THREAD         = 0x00010000
	CLONE_NEWNS          = 0x00020000
	CLONE_SYSVSEM        = 0x00040000
	CLONE_SETTLS         = 0x00080000
	CLONE_PARENT_SETTID  = 0x00100000
	CLONE_CHILD_CLEARTID = 0x00200000
	CLONE_DETACHED       = 0x00400000
	CLONE_UNTRACED       = 0x00800000
	CLONE_CHILD_SETTID   = 0x01000000
	CLONE_NEWCGROUP      = 0x02000000
	CLONE_NEWUTS         = 0x04000000
	CLONE_NEWIPC         = 0x08000000
	CLONE_NEWUSER        = 0x10000000
	CLONE_NEWPID         = 0x20000000
	CLONE_NEWNET         = 0x40000000
	CLONE_IO             = 0x80000000
)

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
		sigs, err := parseSignal(uint16(f))
		if err != nil {
			return fmt.Sprintf("%v", f), err
		}

		fs = append(fs, sigs)
	}

	if len(fs) == 0 {
		return fmt.Sprintf("%v", f), nil
	}

	return strings.Join(fs, "|"), nil
}

var signalMap = map[uint16]string{
	1:  "SIGHUP",
	2:  "SIGINT",
	3:  "SIGQUIT",
	4:  "SIGILL",
	5:  "SIGTRAP",
	6:  "SIGABRT",
	7:  "SIGBUS",
	8:  "SIGFPE",
	9:  "SIGKILL",
	10: "SIGUSR1",
	11: "SIGSEGV",
	12: "SIGUSR2",
	13: "SIGPIPE",
	14: "SIGALRM",
	15: "SIGTERM",
	16: "SIGSTKFLT",
	17: "SIGCHLD",
	18: "SIGCONT",
	19: "SIGSTOP",
	20: "SIGTSTP",
	21: "SIGTTIN",
	22: "SIGTTOU",
	23: "SIGURG",
	24: "SIGXCPU",
	25: "SIGXFSZ",
	26: "SIGVTALRM",
	27: "SIGPROF",
	28: "SIGWINCH",
	29: "SIGIO",
	30: "SIGPWR",
	31: "SIGSYS",
}

func parseSignal(sig uint16) (string, error) {
	name, ok := signalMap[sig]
	if !ok {
		return fmt.Sprintf("%v", sig), nil
	}

	return name, nil
}

func parseOpenMode(mode any) (string, error) {
	m, ok := mode.(uint32)
	if !ok {
		return fmt.Sprintf("%v", mode), transformErr.Throwf("parseOpenMode: parse value error expected %T received %T", m, mode)
	}

	return fmt.Sprintf("%04o", m), nil
}

const (
	O_ACCMODE   = 0003
	O_RDONLY    = 00
	O_WRONLY    = 01
	O_RDWR      = 02
	O_CREAT     = 0100
	O_EXCL      = 0200
	O_NOCTTY    = 0400
	O_TRUNC     = 01000
	O_APPEND    = 02000
	O_NONBLOCK  = 04000
	O_SYNC      = 04010000
	O_ASYNC     = 020000
	O_LARGEFILE = 0100000
	O_DIRECTORY = 0200000
	O_NOFOLLOW  = 0400000
	O_CLOEXEC   = 02000000
	O_DIRECT    = 040000
	O_NOATIME   = 01000000
	O_PATH      = 010000000
	O_DSYNC     = 010000
	O_TMPFILE   = 020000000
)

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

func parseOpenFlags(flags any) (string, error) {
	f, ok := flags.(int32)
	if !ok {
		return fmt.Sprintf("%v", f), transformErr.Throwf("parseOpenFlags: parse value error expected %T received %T", f, flags)
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

func parseOpenat2Flags(flags any) (string, error) {
	f, ok := flags.(int64)
	if !ok {
		return fmt.Sprintf("%v", f), transformErr.Throwf("parseOpenat2Flags: parse value error expected %T received %T", f, flags)
	}

	return parseOpenFlags(int32(f))
}

func parseOpenat2Mode(mode any) (string, error) {
	m, ok := mode.(int64)
	if !ok {
		return fmt.Sprintf("%v", m), transformErr.Throwf("parseOpenat2Mode: parse value error expected %T received %T", m, mode)
	}

	return parseOpenMode(uint32(m))
}

const (
	RESOLVE_NO_XDEV       = 0x01
	RESOLVE_NO_MAGICLINKS = 0x02
	RESOLVE_NO_SYMLINKS   = 0x04
	RESOLVE_BENEATH       = 0x08
	RESOLVE_IN_ROOT       = 0x10
	RESOLVE_CACHED        = 0x20
)

var openat2ResolveFlags = map[int64]string{
	RESOLVE_NO_XDEV:       "RESOLVE_NO_XDEV",
	RESOLVE_NO_MAGICLINKS: "RESOLVE_NO_MAGICLINKS",
	RESOLVE_NO_SYMLINKS:   "RESOLVE_NO_SYMLINKS",
	RESOLVE_BENEATH:       "RESOLVE_BENEATH",
	RESOLVE_IN_ROOT:       "RESOLVE_IN_ROOT",
	RESOLVE_CACHED:        "RESOLVE_CACHED",
}

func parseOpenat2Resolve(resovle any) (string, error) {
	r, ok := resovle.(int64)
	if !ok {
		return fmt.Sprintf("%v", r), transformErr.Throwf("parseOpenat2Resolve: parse value error expected %T received %T", r, resovle)
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

const (
	AF_UNIX  = 1
	AF_INET  = 2
	AF_INET6 = 10
)

var socketFamilyNames = map[int32]string{
	0:  "AF_UNSPEC",
	1:  "AF_UNIX",
	2:  "AF_INET",
	3:  "AF_AX2",
	4:  "AF_IPX",
	5:  "AF_APPLETALK",
	6:  "AF_NETROM",
	7:  "AF_BRIDGE",
	8:  "AF_ATMPVC",
	9:  "AF_X25",
	10: "AF_INET6",
	11: "AF_ROSE",
	12: "AF_DECnet",
	13: "AF_NETBEUI",
	14: "AF_SECURITY",
	15: "AF_KEY",
	16: "AF_NETLINK",
	17: "AF_PACKET",
	18: "AF_ASH",
	19: "AF_ECONET",
	20: "AF_ATMSVC",
	21: "AF_RDS",
	22: "AF_SNA",
	23: "AF_IRDA",
	24: "AF_PPPOX",
	25: "AF_WANPIPE",
	26: "AF_LLC",
	27: "AF_IB",
	28: "AF_MPLS",
	29: "AF_CAN",
	30: "AF_TIPC",
	31: "AF_BLUETOOTH",
	32: "AF_IUCV",
	33: "AF_RXRPC",
	34: "AF_ISDN",
	35: "AF_PHONET",
	36: "AF_IEEE802154",
	37: "AF_CAIF",
	38: "AF_ALG",
	39: "AF_NFC",
	40: "AF_VSOCK",
	41: "AF_KCM",
	42: "AF_QIPCRTR",
	43: "AF_SMC",
	44: "AF_XDP",
}

func parseSocketFamily(n any) (string, error) {
	f, ok := n.(int32)
	if !ok {
		return fmt.Sprintf("%v", f), transformErr.Throwf("parseSocketFamily: parse value error expected %T received %T", f, n)
	}

	if name, ok := socketFamilyNames[f]; ok {
		return name, nil
	}

	return fmt.Sprintf("%v", f), nil
}

var socketTypes = map[int32]string{
	1:  "SOCK_STREAM",
	2:  "SOCK_DGRAM",
	3:  "SOCK_RAW",
	4:  "SOCK_RDM",
	5:  "SOCK_SEQPACKET",
	6:  "SOCK_DCCP",
	10: "SOCK_PACKET",
}

const (
	SOCK_CLOEXEC  = 02000000
	SOCK_NONBLOCK = 00004000
)

func parseSocketType(n any) (string, error) {
	t, ok := n.(int32)
	if !ok {
		return fmt.Sprintf("%v", t), transformErr.Throwf("parseSocketType: parse value error expected %T received %T", t, n)
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

var socketProtocols = map[int32]string{
	0:   "IPPROTO_IP",
	1:   "IPPROTO_ICMP",
	2:   "IPPROTO_IGMP",
	4:   "IPPROTO_IPIP",
	6:   "IPPROTO_TCP",
	8:   "IPPROTO_EGP",
	12:  "IPPROTO_PUP",
	17:  "IPPROTO_UDP",
	22:  "IPPROTO_IDP",
	29:  "IPPROTO_TP",
	33:  "IPPROTO_DCCP",
	41:  "IPPROTO_IPV6",
	46:  "IPPROTO_RSVP",
	47:  "IPPROTO_GRE",
	50:  "IPPROTO_ESP",
	51:  "IPPROTO_AH",
	92:  "IPPROTO_MTP",
	94:  "IPPROTO_BEETPH",
	98:  "IPPROTO_ENCAP",
	103: "IPPROTO_PIM",
	108: "IPPROTO_COMP",
	132: "IPPROTO_SCTP",
	136: "IPPROTO_UDPLITE",
	137: "IPPROTO_MPLS",
	255: "IPPROTO_RAW",
}

func parseSocketProtocol(n any) (string, error) {
	p, ok := n.(int32)
	if !ok {
		return fmt.Sprintf("%v", p), transformErr.Throwf("parseSocketProtocol: parse value error expected %T received %T", p, n)
	}

	if prot, ok := socketProtocols[p]; ok {
		return prot, nil
	}

	return fmt.Sprintf("%v", p), nil
}
