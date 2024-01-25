// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"fmt"
	"strings"
)

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

func parseExecveatDird(dird any) (string, error) {
	d, ok := dird.(int32)
	if !ok {
		return fmt.Sprintf("%v", dird), fmt.Errorf("parseExecveatDird: parse value error")
	}

	if d == AT_FDCWD {
		return "AT_FDCWD", nil
	}

	if d == AT_EMPTY_PATH {
		return "AT_EMPTY_PATH", nil
	}

	return fmt.Sprintf("%v", d), nil
}

func parseExecveatFlags(flag any) (string, error) {
	f, ok := flag.(int32)
	if !ok {
		return fmt.Sprintf("%v", flag), fmt.Errorf("parseExecveatFlags: parse value error")
	}

	var fs []string
	if f&AT_EMPTY_PATH == AT_EMPTY_PATH {
		fs = append(fs, "AT_EMPTY_PATH")
	}

	if f&AT_SYMLINK_NOFOLLOW == AT_SYMLINK_NOFOLLOW {
		fs = append(fs, "AT_SYMLINK_NOFOLLOW")
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

func parseCloneFlags(flag any) (string, error) {
	f, ok := flag.(uint64)
	if !ok {
		return fmt.Sprintf("%v", flag), fmt.Errorf("parseCloneFlags: parse value error")
	}

	var fs []string
	if f&CSIGNAL == CSIGNAL {
		f -= CSIGNAL
		fs = append(fs, "CSIGNAL")
	}

	if f&CLONE_VM == CLONE_VM {
		f -= CLONE_VM
		fs = append(fs, "CLONE_VM")
	}

	if f&CLONE_FS == CLONE_FS {
		f -= CLONE_FS
		fs = append(fs, "CLONE_FS")
	}

	if f&CLONE_FILES == CLONE_FILES {
		f -= CLONE_FILES
		fs = append(fs, "CLONE_FILES")
	}

	if f&CLONE_SIGHAND == CLONE_SIGHAND {
		f -= CLONE_SIGHAND
		fs = append(fs, "CLONE_SIGHAND")
	}

	if f&CLONE_PIDFD == CLONE_PIDFD {
		f -= CLONE_PIDFD
		fs = append(fs, "CLONE_PIDFD")
	}

	if f&CLONE_PTRACE == CLONE_PTRACE {
		f -= CLONE_PTRACE
		fs = append(fs, "CLONE_PTRACE")
	}

	if f&CLONE_VFORK == CLONE_VFORK {
		f -= CLONE_VFORK
		fs = append(fs, "CLONE_VFORK")
	}

	if f&CLONE_PARENT == CLONE_PARENT {
		f -= CLONE_PARENT
		fs = append(fs, "CLONE_PARENT")
	}

	if f&CLONE_THREAD == CLONE_THREAD {
		f -= CLONE_THREAD
		fs = append(fs, "CLONE_THREAD")
	}

	if f&CLONE_NEWNS == CLONE_NEWNS {
		f -= CLONE_NEWNS
		fs = append(fs, "CLONE_NEWNS")
	}

	if f&CLONE_SYSVSEM == CLONE_SYSVSEM {
		f -= CLONE_SYSVSEM
		fs = append(fs, "CLONE_SYSVSEM")
	}

	if f&CLONE_SETTLS == CLONE_SETTLS {
		f -= CLONE_SETTLS
		fs = append(fs, "CLONE_SETTLS")
	}

	if f&CLONE_PARENT_SETTID == CLONE_PARENT_SETTID {
		f -= CLONE_PARENT_SETTID
		fs = append(fs, "CLONE_PARENT_SETTID")
	}

	if f&CLONE_CHILD_CLEARTID == CLONE_CHILD_CLEARTID {
		f -= CLONE_CHILD_CLEARTID
		fs = append(fs, "CLONE_CHILD_CLEARTID")
	}

	if f&CLONE_DETACHED == CLONE_DETACHED {
		f -= CLONE_DETACHED
		fs = append(fs, "CLONE_DETACHED")
	}

	if f&CLONE_UNTRACED == CLONE_UNTRACED {
		f -= CLONE_UNTRACED
		fs = append(fs, "CLONE_UNTRACED")
	}

	if f&CLONE_CHILD_SETTID == CLONE_CHILD_SETTID {
		f -= CLONE_CHILD_SETTID
		fs = append(fs, "CLONE_CHILD_SETTID")
	}

	if f&CLONE_NEWCGROUP == CLONE_NEWCGROUP {
		f -= CLONE_NEWCGROUP
		fs = append(fs, "CLONE_NEWCGROUP")
	}

	if f&CLONE_NEWUTS == CLONE_NEWUTS {
		f -= CLONE_NEWUTS
		fs = append(fs, "CLONE_NEWUTS")
	}

	if f&CLONE_NEWIPC == CLONE_NEWIPC {
		f -= CLONE_NEWIPC
		fs = append(fs, "CLONE_NEWIPC")
	}

	if f&CLONE_NEWUSER == CLONE_NEWUSER {
		f -= CLONE_NEWUSER
		fs = append(fs, "CLONE_NEWUSER")
	}

	if f&CLONE_NEWPID == CLONE_NEWPID {
		f -= CLONE_NEWPID
		fs = append(fs, "CLONE_NEWPID")
	}

	if f&CLONE_NEWNET == CLONE_NEWNET {
		f -= CLONE_NEWNET
		fs = append(fs, "CLONE_NEWNET")
	}

	if f&CLONE_IO == CLONE_IO {
		f -= CLONE_IO
		fs = append(fs, "CLONE_IO")
	}

	sigs, err := parseSignal(uint16(f))
	if err != nil {
		return fmt.Sprintf("%v", f), err
	}

	fs = append(fs, sigs)
	if len(fs) == 0 {
		return fmt.Sprintf("%v", f), nil
	}

	return strings.Join(fs, "|"), nil
}

func parseSignal(sig uint16) (string, error) {
	switch sig {
	case 1:
		return "SIGHUP", nil
	case 2:
		return "SIGINT", nil
	case 3:
		return "SIGQUIT", nil
	case 4:
		return "SIGILL", nil
	case 5:
		return "SIGTRAP", nil
	case 6:
		return "SIGABRT", nil
	case 7:
		return "SIGBUS", nil
	case 8:
		return "SIGFPE", nil
	case 9:
		return "SIGKILL", nil
	case 10:
		return "SIGUSR1", nil
	case 11:
		return "SIGSEGV", nil
	case 12:
		return "SIGUSR2", nil
	case 13:
		return "SIGPIPE", nil
	case 14:
		return "SIGALRM", nil
	case 15:
		return "SIGTERM", nil
	case 16:
		return "SIGSTKFLT", nil
	case 17:
		return "SIGCHLD", nil
	case 18:
		return "SIGCONT", nil
	case 19:
		return "SIGSTOP", nil
	case 20:
		return "SIGTSTP", nil
	case 21:
		return "SIGTTIN", nil
	case 22:
		return "SIGTTOU", nil
	case 23:
		return "SIGURG", nil
	case 24:
		return "SIGXCPU", nil
	case 25:
		return "SIGXFSZ", nil
	case 26:
		return "SIGVTALRM", nil
	case 27:
		return "SIGPROF", nil
	case 28:
		return "SIGWINCH", nil
	case 29:
		return "SIGIO", nil
	case 30:
		return "SIGPWR", nil
	case 31:
		return "SIGSYS", nil
	default:
		return "", nil
	}
}