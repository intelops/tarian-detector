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
	Comm      [16]uint8
	Cwd       [32]uint8
	NodeInfo  struct {
		Sysname    [65]uint8
		Nodename   [65]uint8
		Release    [65]uint8
		Version    [65]uint8
		Machine    [65]uint8
		Domainname [65]uint8
	}
}

type NodeInfo struct {
	Sysname    string
	Nodename   string
	Release    string
	Version    string
	Machine    string
	Domainname string
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

	res_data["node_info"] = NodeInfo{
		Sysname:    Uint8toString(ec.NodeInfo.Sysname[:]),
		Nodename:   Uint8toString(ec.NodeInfo.Nodename[:]),
		Release:    Uint8toString(ec.NodeInfo.Release[:]),
		Version:    Uint8toString(ec.NodeInfo.Version[:]),
		Machine:    Uint8toString(ec.NodeInfo.Machine[:]),
		Domainname: Uint8toString(ec.NodeInfo.Domainname[:]),
	}

	return res_data
}
