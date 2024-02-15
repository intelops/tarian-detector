// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"fmt"
	"strings"

	"github.com/intelops/tarian-detector/pkg/err"
)

var tansformerErr = err.New("eventparser.transformer")

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
		return fmt.Sprintf("%v", dird), tansformerErr.Throwf("parseExecveatDird: parse value error expected %T received %T", d, dird)
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
		return fmt.Sprintf("%v", flag), tansformerErr.Throwf("parseExecveatFlags: parse value error expected %T received %T", f, flag)
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
		return fmt.Sprintf("%v", flag), tansformerErr.Throwf("parseCloneFlags: parse value error expected %T received %T", f, flag)
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
		return fmt.Sprintf("%v", mode), tansformerErr.Throwf("parseOpenMode: parse value error expected %T received %T", m, mode)
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
		return fmt.Sprintf("%v", f), tansformerErr.Throwf("parseOpenFlags: parse value error expected %T received %T", f, flags)
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
		return fmt.Sprintf("%v", f), tansformerErr.Throwf("parseOpenat2Flags: parse value error expected %T received %T", f, flags)
	}

	return parseOpenFlags(int32(f))
}

func parseOpenat2Mode(mode any) (string, error) {
	m, ok := mode.(int64)
	if !ok {
		return fmt.Sprintf("%v", m), tansformerErr.Throwf("parseOpenat2Mode: parse value error expected %T received %T", m, mode)
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
		return fmt.Sprintf("%v", r), tansformerErr.Throwf("parseOpenat2Resolve: parse value error expected %T received %T", r, resovle)
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
	AF_UNSPEC     = 0
	AF_UNIX       = 1
	AF_INET       = 2
	AF_AX2        = 3
	AF_IPX        = 4
	AF_APPLETALK  = 5
	AF_NETROM     = 6
	AF_BRIDGE     = 7
	AF_ATMPVC     = 8
	AF_X25        = 9
	AF_INET6      = 10
	AF_ROSE       = 11
	AF_DECnet     = 12
	AF_NETBEUI    = 13
	AF_SECURITY   = 14
	AF_KEY        = 15
	AF_NETLINK    = 16
	AF_PACKET     = 17
	AF_ASH        = 18
	AF_ECONET     = 19
	AF_ATMSVC     = 20
	AF_RDS        = 21
	AF_SNA        = 22
	AF_IRDA       = 23
	AF_PPPOX      = 24
	AF_WANPIPE    = 25
	AF_LLC        = 26
	AF_IB         = 27
	AF_MPLS       = 28
	AF_CAN        = 29
	AF_TIPC       = 30
	AF_BLUETOOTH  = 31
	AF_IUCV       = 32
	AF_RXRPC      = 33
	AF_ISDN       = 34
	AF_PHONET     = 35
	AF_IEEE802154 = 36
	AF_CAIF       = 37
	AF_ALG        = 38
	AF_NFC        = 39
	AF_VSOCK      = 40
	AF_KCM        = 41
	AF_QIPCRTR    = 42
	AF_SMC        = 43
	AF_XDP        = 44
)

func parseSocketFamily(n any) (string, error) {
	f, ok := n.(int32)
	if !ok {
		return fmt.Sprintf("%v", f), fmt.Errorf("parseSocketFamily: parse value error")
	}

	switch f {
	case AF_UNSPEC:
		return "AF_UNSPEC", nil
	case AF_UNIX:
		return "AF_UNIX", nil
	case AF_INET:
		return "AF_INET", nil
	case AF_AX2:
		return "AF_AX2", nil
	case AF_IPX:
		return "AF_IPX", nil
	case AF_APPLETALK:
		return "AF_APPLETALK", nil
	case AF_NETROM:
		return "AF_NETROM", nil
	case AF_BRIDGE:
		return "AF_BRIDGE", nil
	case AF_ATMPVC:
		return "AF_ATMPVC", nil
	case AF_X25:
		return "AF_X25", nil
	case AF_INET6:
		return "AF_INET6", nil
	case AF_ROSE:
		return "AF_ROSE", nil
	case AF_DECnet:
		return "AF_DECnet", nil
	case AF_NETBEUI:
		return "AF_NETBEUI", nil
	case AF_SECURITY:
		return "AF_SECURITY", nil
	case AF_KEY:
		return "AF_KEY", nil
	case AF_NETLINK:
		return "AF_NETLINK", nil
	case AF_PACKET:
		return "AF_PACKET", nil
	case AF_ASH:
		return "AF_ASH", nil
	case AF_ECONET:
		return "AF_ECONET", nil
	case AF_ATMSVC:
		return "AF_ATMSVC", nil
	case AF_RDS:
		return "AF_RDS", nil
	case AF_SNA:
		return "AF_SNA", nil
	case AF_IRDA:
		return "AF_IRDA", nil
	case AF_PPPOX:
		return "AF_PPPOX", nil
	case AF_WANPIPE:
		return "AF_WANPIPE", nil
	case AF_LLC:
		return "AF_LLC", nil
	case AF_IB:
		return "AF_IB", nil
	case AF_MPLS:
		return "AF_MPLS", nil
	case AF_CAN:
		return "AF_CAN", nil
	case AF_TIPC:
		return "AF_TIPC", nil
	case AF_BLUETOOTH:
		return "AF_BLUETOOTH", nil
	case AF_IUCV:
		return "AF_IUCV", nil
	case AF_RXRPC:
		return "AF_RXRPC", nil
	case AF_ISDN:
		return "AF_ISDN", nil
	case AF_PHONET:
		return "AF_PHONET", nil
	case AF_IEEE802154:
		return "AF_IEEE802154", nil
	case AF_CAIF:
		return "AF_CAIF", nil
	case AF_ALG:
		return "AF_ALG", nil
	case AF_NFC:
		return "AF_NFC", nil
	case AF_VSOCK:
		return "AF_VSOCK", nil
	case AF_KCM:
		return "AF_KCM", nil
	case AF_QIPCRTR:
		return "AF_QIPCRTR", nil
	case AF_SMC:
		return "AF_SMC", nil
	case AF_XDP:
		return "AF_XDP", nil
	default:
		return fmt.Sprintf("%v", f), nil
	}
}

const (
	SOCK_STREAM    = 1
	SOCK_DGRAM     = 2
	SOCK_RAW       = 3
	SOCK_RDM       = 4
	SOCK_SEQPACKET = 5
	SOCK_DCCP      = 6
	SOCK_PACKET    = 10
	SOCK_CLOEXEC   = 02000000
	SOCK_NONBLOCK  = 00004000
)

func parseSocketType(n any) (string, error) {
	t, ok := n.(int32)
	if !ok {
		return fmt.Sprintf("%v", t), fmt.Errorf("parseSocketType: parse value error")
	}

	var ts []string
	switch t & 0xf {
	case SOCK_STREAM:
		ts = append(ts, "SOCK_STREAM")
	case SOCK_DGRAM:
		ts = append(ts, "SOCK_DGRAM")
	case SOCK_RAW:
		ts = append(ts, "SOCK_RAW")
	case SOCK_RDM:
		ts = append(ts, "SOCK_RDM")
	case SOCK_SEQPACKET:
		ts = append(ts, "SOCK_SEQPACKET")
	case SOCK_DCCP:
		ts = append(ts, "SOCK_DCCP")
	case SOCK_PACKET:
		ts = append(ts, "SOCK_PACKET")
	default:
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

const (
	IPPROTO_IP      = 0
	IPPROTO_ICMP    = 1
	IPPROTO_IGMP    = 2
	IPPROTO_IPIP    = 4
	IPPROTO_TCP     = 6
	IPPROTO_EGP     = 8
	IPPROTO_PUP     = 12
	IPPROTO_UDP     = 17
	IPPROTO_IDP     = 22
	IPPROTO_TP      = 29
	IPPROTO_DCCP    = 33
	IPPROTO_IPV6    = 41
	IPPROTO_RSVP    = 46
	IPPROTO_GRE     = 47
	IPPROTO_ESP     = 50
	IPPROTO_AH      = 51
	IPPROTO_MTP     = 92
	IPPROTO_BEETPH  = 94
	IPPROTO_ENCAP   = 98
	IPPROTO_PIM     = 103
	IPPROTO_COMP    = 108
	IPPROTO_SCTP    = 132
	IPPROTO_UDPLITE = 136
	IPPROTO_MPLS    = 137
	IPPROTO_RAW     = 255
)

func parseSocketProtocol(n any) (string, error) {
	p, ok := n.(int32)
	if !ok {
		return fmt.Sprintf("%v", p), fmt.Errorf("parseSocketProtocol: parse value error")
	}

	switch p {
	case IPPROTO_IP:
		return "IPPROTO_IP", nil
	case IPPROTO_ICMP:
		return "IPPROTO_ICMP", nil
	case IPPROTO_IGMP:
		return "IPPROTO_IGMP", nil
	case IPPROTO_IPIP:
		return "IPPROTO_IPIP", nil
	case IPPROTO_TCP:
		return "IPPROTO_TCP", nil
	case IPPROTO_EGP:
		return "IPPROTO_EGP", nil
	case IPPROTO_PUP:
		return "IPPROTO_PUP", nil
	case IPPROTO_UDP:
		return "IPPROTO_UDP", nil
	case IPPROTO_IDP:
		return "IPPROTO_IDP", nil
	case IPPROTO_TP:
		return "IPPROTO_TP", nil
	case IPPROTO_DCCP:
		return "IPPROTO_DCCP", nil
	case IPPROTO_IPV6:
		return "IPPROTO_IPV6", nil
	case IPPROTO_RSVP:
		return "IPPROTO_RSVP", nil
	case IPPROTO_GRE:
		return "IPPROTO_GRE", nil
	case IPPROTO_ESP:
		return "IPPROTO_ESP", nil
	case IPPROTO_AH:
		return "IPPROTO_AH", nil
	case IPPROTO_MTP:
		return "IPPROTO_MTP", nil
	case IPPROTO_BEETPH:
		return "IPPROTO_BEETPH", nil
	case IPPROTO_ENCAP:
		return "IPPROTO_ENCAP", nil
	case IPPROTO_PIM:
		return "IPPROTO_PIM", nil
	case IPPROTO_COMP:
		return "IPPROTO_COMP", nil
	case IPPROTO_SCTP:
		return "IPPROTO_SCTP", nil
	case IPPROTO_UDPLITE:
		return "IPPROTO_UDPLITE", nil
	case IPPROTO_MPLS:
		return "IPPROTO_MPLS", nil
	case IPPROTO_RAW:
		return "IPPROTO_RAW", nil
	default:
		return fmt.Sprintf("%v", p), nil
	}
}
