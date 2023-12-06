// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package utils

type EventContext struct {
	Ts        uint64
	StartTime uint64
	Pid       uint32
	Tgid      uint32
	Ppid      uint32
	Glpid     uint32
	Uid       uint32
	Gid       uint32
	MountId   int32
	MountNsId uint32
	CgroupId  uint64
	NodeInfo  struct {
		Sysname    [65]uint8
		Nodename   [65]uint8
		Release    [65]uint8
		Version    [65]uint8
		Machine    [65]uint8
		Domainname [65]uint8
	}
	Comm         [16]uint8
	Cwd          [32]uint8
	MountDevname [256]uint8
}

type Node struct {
	Sysname    string
	Nodename   string
	Release    string
	Version    string
	Machine    string
	Domainname string
}

type Mount struct {
	MountId          int32
	MountNameSpaceId uint32
	MountDeviceName  string
}

func SetContext(ec EventContext) map[string]any {
	res_data := make(map[string]any)

	res_data["boot_time"] = NanoSecToTimeFormat(ec.Ts)
	res_data["start_time"] = NanoSecToTimeFormat(ec.StartTime)

	res_data["process_id"] = ec.Pid
	res_data["thread_group_id"] = ec.Tgid

	res_data["parent_process_id"] = ec.Ppid
	res_data["group_leader_process_id"] = ec.Glpid

	res_data["user_id"] = ec.Uid
	res_data["group_id"] = ec.Gid

	res_data["command"] = Uint8toString(ec.Comm[:])

	res_data["current_working_directory"] = Uint8toString(ec.Cwd[:])

	res_data["cgroup_id"] = ec.CgroupId

	res_data["node"] = Node{
		Sysname:    Uint8toString(ec.NodeInfo.Sysname[:]),
		Nodename:   Uint8toString(ec.NodeInfo.Nodename[:]),
		Release:    Uint8toString(ec.NodeInfo.Release[:]),
		Version:    Uint8toString(ec.NodeInfo.Version[:]),
		Machine:    Uint8toString(ec.NodeInfo.Machine[:]),
		Domainname: Uint8toString(ec.NodeInfo.Domainname[:]),
	}

	res_data["mount"] = Mount{
		MountId:          ec.MountId,
		MountNameSpaceId: ec.MountNsId,
		MountDeviceName:  Uint8toString(ec.MountDevname[:]),
	}

	return res_data
}
