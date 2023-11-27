// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package eventparser

type EventContext struct {
	Context struct {
		Ts   uint64
		Task struct {
			StartTime     uint64
			HostPid       uint32
			HostTgid      uint32
			HostPpid      uint32
			Pid           uint32
			Tgid          uint32
			Ppid          uint32
			Uid           uint32
			Gid           uint32
			CgroupId      uint64
			MountNsId     uint64
			PidNsId       uint64
			ExecId        uint64
			ParentExecId  uint64
			EexecId       uint64
			EparentExecId uint64
			Comm          [16]byte
			Cwd           [4096]byte
		}
		EventId     uint32
		Syscall     int32
		ProcessorId uint16
	}
	Buf struct {
		NumFields  uint8
		FieldTypes uint64
		Data       [10240]byte
	}
	SystemInfo struct {
		Sysname    [65]byte
		Nodename   [65]byte
		Release    [65]byte
		Version    [65]byte
		Machine    [65]byte
		Domainname [65]byte
	}
}
