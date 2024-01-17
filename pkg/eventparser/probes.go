// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package eventparser

import "fmt"

type SysArg struct {
	Name        string
	Description string
	TarianType  string
	LinuxType   string
	Function    func(any) (string, error)
}

type Syscall struct {
	Id   int
	Name string
	Args []SysArg
}

type Arg struct {
	Name  string
	Value string
}

var syscalls = map[int32]Syscall{
	0: {
		Id:   0,
		Name: "sys_read",
		Args: []SysArg{
			0: {
				Name: "file_descriptor",
			},
			1: {
				Name: "buf",
			},
			2: {
				Name: "count",
			},
		},
	},
	1: {
		Id:   1,
		Name: "sys_write",
		Args: []SysArg{
			0: {
				Name: "file_descriptor",
			},
			1: {
				Name: "buf",
			},
			2: {
				Name: "count",
			},
		},
	},
	2: {
		Id:   2,
		Name: "sys_open",
		Args: []SysArg{
			0: {
				Name:      "filename",
				LinuxType: "unsigned int",
			},
			1: {
				Name:      "flags",
				LinuxType: "int",
			},
			2: {
				Name:      "mode",
				LinuxType: "short unsigned int",
			},
		},
	},
	3: {
		Id:   3,
		Name: "sys_close",
		Args: []SysArg{
			0: {
				Name:      "file_descriptor",
				LinuxType: "unsigned int",
			},
		},
	},
	19: {
		Id:   19,
		Name: "sys_readv",
		Args: []SysArg{
			0: {
				Name: "file_descriptor",
			},
			1: {
				Name: "vector",
			},
			2: {
				Name: "vector_len",
			},
		},
	},
	20: {
		Id:   20,
		Name: "sys_writev",
		Args: []SysArg{
			0: {
				Name: "file_descriptor",
			},
			1: {
				Name: "vector",
			},
			2: {
				Name: "vector_len",
			},
		},
	},
	41: {
		Id:   41,
		Name: "sys_accept",
		Args: []SysArg{
			0: {
				Name: "file_descriptor",
			},
			1: {
				Name: "upeer_sockaddr",
			},
			2: {
				Name: "upeer_addrlen",
			},
		},
	},
	42: {
		Id:   42,
		Name: "sys_connect",
		Args: []SysArg{
			0: {
				Name: "file_descriptor",
			},
			1: {
				Name: "uservaddr",
			},
			2: {
				Name: "addrlen",
			},
		},
	},
	43: {
		Id:   43,
		Name: "sys_socket",
		Args: []SysArg{
			0: {
				Name: "family",
			},
			1: {
				Name: "LinuxType",
			},
			2: {
				Name: "protocol",
			},
		},
	},
	49: {
		Id:   49,
		Name: "sys_bind",
		Args: []SysArg{
			0: {
				Name: "file_descriptor",
			},
			1: {
				Name: "umyaddr",
			},
			2: {
				Name: "addrlen",
			},
		},
	},
	50: {
		Id:   50,
		Name: "sys_listen",
		Args: []SysArg{
			0: {
				Name: "file_descriptor",
			},
			1: {
				Name: "backlog",
			},
		},
	},
	59: {
		Id:   59,
		Name: "sys_execve",
		Args: []SysArg{
			0: {
				Name: "filename",
			},
			1: {
				Name: "argv",
			},
			2: {
				Name: "envs",
			},
		},
	},
	257: {
		Id:   257,
		Name: "sys_openat",
		Args: []SysArg{
			0: {
				Name:      "directory_file_descriptor",
				LinuxType: "int",
			},
			1: {
				Name:      "filename",
				LinuxType: "int",
			},
			2: {
				Name: "flags",
			},
			3: {
				Name:      "mode",
				LinuxType: "short unsigned int",
			},
		},
	},
	322: {
		Id:   322,
		Name: "sys_execveat",
		Args: []SysArg{
			0: {
				Name: "file_descriptor",
			},
			1: {
				Name: "filename",
			},
			2: {
				Name: "argv",
			},
			3: {
				Name: "envp",
			},
			4: {
				Name: "flags",
			},
		},
	},
	437: {
		Id:   437,
		Name: "sys_openat2",
		Args: []SysArg{
			0: {
				Name:      "directory_file_descriptor",
				LinuxType: "int",
			},
			1: {
				Name:      "filename",
				LinuxType: "int",
			},
			2: {
				Name:      "how",
				LinuxType: "struct open_how",
			},
			3: {
				Name:      "usize",
				LinuxType: "size_t",
			},
		},
	},
}

func (s *SysArg) ParseArg(val interface{}) (Arg, error) {
	arg := Arg{}

	if s.Function != nil {
		parsedValue, err := s.Function(val)
		if err != nil {
			return arg, err
		}
		arg.Value = parsedValue
	} else {
		arg.Value = fmt.Sprintf("%v", val)
	}

	arg.Name = s.Name

	return arg, nil
}
