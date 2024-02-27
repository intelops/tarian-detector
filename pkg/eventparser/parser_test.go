// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"fmt"
	"reflect"
	"testing"
)

// TestNewByteStream tests the NewByteStream function.
func TestNewByteStream(t *testing.T) {
	type args struct {
		inputData []byte
		n         uint8
	}
	tests := []struct {
		name string
		args args
		want *ByteStream
	}{
		{
			name: "valid values",
			args: args{
				inputData: []byte{1, 2, 3, 4, 5, 6, 7, 8},
				n:         8,
			},
			want: &ByteStream{
				data:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
				position: 0,
				nparams:  8,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewByteStream(tt.args.inputData, tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewByteStream() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseByteArray tests the ParseByteArray function.
func TestParseByteArray(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name       string
		args       args
		loadEvents bool
		want       map[string]any
		wantErr    bool
	}{
		{
			name: "buffer size lessthan 4",
			args: args{
				data: []byte{1, 2, 3},
			},
			loadEvents: false,
			want:       nil,
			wantErr:    true,
		},
		{
			name: "invalid event id",
			args: args{
				data: []byte{1, 2, 3, 4},
			},
			loadEvents: false,
			want:       nil,
			wantErr:    true,
		},
		{
			name: "invalid buffer",
			args: args{
				data: []byte{12, 0, 0, 0, 5, 6, 7, 8, 9},
			},
			loadEvents: true,
			want:       nil,
			wantErr:    true,
		},
		{
			name: "error parse params",
			args: args{
				data: func() []byte {
					data := make([]byte, 764)

					data[0] = 12 // eventId
					data[4] = 2  // nparams

					return data
				}(),
			},
			loadEvents: true,
			want:       nil,
			wantErr:    true,
		},
		{
			name: "error nparams > actual written params",
			args: args{
				data: func() []byte {
					data := make([]byte, 765+7)

					data[0] = 12 // eventId
					data[4] = 4  // nparams

					return data
				}(),
			},
			loadEvents: true,
			want: map[string]any{
				"eventId":             "sys_write_entry",
				"timestamp":           uint64(0),
				"syscallId":           int32(1),
				"processor":           uint16(0),
				"threadStartTime":     uint64(0),
				"hostProcessId":       uint32(0),
				"hostThreadId":        uint32(0),
				"hostParentProcessId": uint32(0),
				"processId":           uint32(0),
				"threadId":            uint32(0),
				"parentProcessId":     uint32(0),
				"userId":              uint32(0),
				"groupId":             uint32(0),
				"cgroupId":            uint64(0),
				"mountNamespace":      uint64(0),
				"pidNamespace":        uint64(0),
				"execId":              uint64(0),
				"parentExecId":        uint64(0),
				"processName":         "",
				"directory":           "",
				"sysname":             "",
				"nodename":            "",
				"release":             "",
				"version":             "",
				"machine":             "",
				"domainname":          "",
				"context": []arg{
					{
						Name:       "fd",
						Value:      "0",
						TarianType: 7,
						LinuxType:  "int",
					},
					{
						Name:       "buf",
						Value:      fmt.Sprintf("%v", []byte{}),
						TarianType: 12,
						LinuxType:  "const char *",
					},
					{
						Name:       "count",
						Value:      "0",
						TarianType: 3,
						LinuxType:  "size_t",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid sys_write_entry record parsing",
			args: args{
				data: []byte{12, 0, 0, 0, 3, 1, 0, 0, 0, 19, 2, 55, 188, 204, 13, 0, 0, 0, 0, 85, 79, 20, 171, 7, 0, 0, 0, 170, 12, 0, 0, 170, 12, 0, 0, 66, 7, 0, 0, 170, 12, 0, 0, 170, 12, 0, 0, 66, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 86, 5, 0, 0, 0, 0, 0, 0, 1, 0, 0, 240, 0, 0, 0, 0, 252, 255, 255, 239, 0, 0, 0, 0, 85, 79, 20, 171, 175, 12, 0, 0, 17, 97, 89, 157, 70, 7, 0, 0, 102, 114, 111, 110, 116, 101, 110, 100, 0, 0, 0, 0, 0, 0, 0, 0, 47, 104, 111, 109, 101, 47, 99, 114, 97, 118, 101, 108, 97, 64, 97, 112, 112, 115, 116, 101, 107, 99, 111, 114, 112, 46, 108, 111, 99, 97, 108, 0, 47, 101, 109, 98, 101, 100, 100, 101, 100, 45, 49, 100, 49, 56, 49, 101, 99, 100, 101, 102, 51, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 105, 110, 117, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 67, 76, 80, 84, 68, 65, 76, 48, 54, 51, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 46, 49, 53, 46, 48, 45, 57, 55, 45, 103, 101, 110, 101, 114, 105, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 49, 48, 55, 126, 50, 48, 46, 48, 52, 46, 49, 45, 85, 98, 117, 110, 116, 117, 32, 83, 77, 80, 32, 70, 114, 105, 32, 70, 101, 98, 32, 57, 32, 49, 52, 58, 50, 48, 58, 49, 49, 32, 85, 84, 67, 32, 50, 48, 50, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 56, 54, 95, 54, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 110, 111, 110, 101, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 17, 0, 73, 110, 118, 97, 108, 105, 100, 32, 112, 97, 115, 115, 119, 111, 114, 100, 0, 17, 0, 0, 0},
			},
			loadEvents: true,
			want: map[string]any{
				"eventId":             "sys_write_entry",
				"timestamp":           uint64(15172982211091),
				"syscallId":           int32(1),
				"processor":           uint16(0),
				"threadStartTime":     uint64(32935006037),
				"hostProcessId":       uint32(3242),
				"hostThreadId":        uint32(3242),
				"hostParentProcessId": uint32(1858),
				"processId":           uint32(3242),
				"threadId":            uint32(3242),
				"parentProcessId":     uint32(1858),
				"userId":              uint32(0),
				"groupId":             uint32(0),
				"cgroupId":            uint64(1366),
				"mountNamespace":      uint64(4026531841),
				"pidNamespace":        uint64(4026531836),
				"execId":              uint64(13948629045077),
				"parentExecId":        uint64(7999868985617),
				"processName":         "frontend",
				"directory":           string([]byte{47, 104, 111, 109, 101, 47, 99, 114, 97, 118, 101, 108, 97, 64, 97, 112, 112, 115, 116, 101, 107, 99, 111, 114, 112, 46, 108, 111, 99, 97, 108, 0, 47, 101, 109, 98, 101, 100, 100, 101, 100, 45, 49, 100, 49, 56, 49, 101, 99, 100, 101, 102, 51, 102}),
				"sysname":             "Linux",
				"nodename":            "ACLPTDAL0631",
				"release":             "5.15.0-97-generic",
				"version":             "#107~20.04.1-Ubuntu SMP Fri Feb 9 14:20:11 UTC 2024",
				"machine":             "x86_64",
				"domainname":          "(none)",
				"context": []arg{
					{
						Name:       "fd",
						Value:      "1",
						TarianType: 7,
						LinuxType:  "int",
					},
					{
						Name:       "buf",
						Value:      fmt.Sprintf("%v", []byte{73, 110, 118, 97, 108, 105, 100, 32, 112, 97, 115, 115, 119, 111, 114, 100, 0}),
						TarianType: 12,
						LinuxType:  "const char *",
					},
					{
						Name:       "count",
						Value:      "17",
						TarianType: 3,
						LinuxType:  "size_t",
					},
				},
			},
			wantErr: false,
		},
		{
			name:       "valid sys_socket_entry record parsing",
			loadEvents: true,
			wantErr:    false,
			args: args{
				data: []byte{26, 0, 0, 0, 3, 41, 0, 0, 0, 81, 74, 169, 30, 184, 30, 0, 0, 15, 0, 69, 7, 11, 28, 5, 1, 0, 0, 191, 227, 36, 0, 191, 227, 36, 0, 173, 200, 0, 0, 191, 227, 36, 0, 191, 227, 36, 0, 10, 205, 0, 0, 24, 197, 143, 36, 193, 191, 143, 36, 182, 14, 0, 0, 0, 0, 0, 0, 1, 0, 0, 240, 0, 0, 0, 0, 252, 255, 255, 239, 0, 0, 0, 0, 69, 7, 11, 28, 191, 227, 36, 0, 51, 160, 181, 22, 173, 200, 0, 0, 99, 111, 100, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47, 104, 111, 109, 101, 47, 99, 114, 97, 118, 101, 108, 97, 64, 97, 112, 112, 115, 116, 101, 107, 99, 111, 114, 112, 46, 108, 111, 99, 97, 108, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 105, 110, 117, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 67, 76, 80, 84, 68, 65, 76, 48, 54, 51, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 46, 49, 53, 46, 48, 45, 57, 55, 45, 103, 101, 110, 101, 114, 105, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 49, 48, 55, 126, 50, 48, 46, 48, 52, 46, 49, 45, 85, 98, 117, 110, 116, 117, 32, 83, 77, 80, 32, 70, 114, 105, 32, 70, 101, 98, 32, 57, 32, 49, 52, 58, 50, 48, 58, 49, 49, 32, 85, 84, 67, 32, 50, 48, 50, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 56, 54, 95, 54, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 110, 111, 110, 101, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 1, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			want: map[string]any{
				"eventId":             "sys_socket_entry",
				"timestamp":           uint64(33776137226833),
				"syscallId":           int32(41),
				"processor":           uint16(15),
				"threadStartTime":     uint64(1121456949061),
				"hostProcessId":       uint32(2417599),
				"hostThreadId":        uint32(2417599),
				"hostParentProcessId": uint32(51373),
				"processId":           uint32(2417599),
				"threadId":            uint32(2417599),
				"parentProcessId":     uint32(52490),
				"userId":              uint32(613401880),
				"groupId":             uint32(613400513),
				"cgroupId":            uint64(3766),
				"mountNamespace":      uint64(4026531841),
				"pidNamespace":        uint64(4026531836),
				"execId":              uint64(10383509110327109),
				"parentExecId":        uint64(220645735899187),
				"processName":         "code",
				"directory":           "/home/cravela@appstekcorp.local",
				"sysname":             "Linux",
				"nodename":            "ACLPTDAL0631",
				"release":             "5.15.0-97-generic",
				"version":             "#107~20.04.1-Ubuntu SMP Fri Feb 9 14:20:11 UTC 2024",
				"machine":             "x86_64",
				"domainname":          "(none)",
				"context": []arg{
					{
						Name:       "family",
						Value:      "AF_INET",
						TarianType: 7,
						LinuxType:  "int",
					},
					{
						Name:       "type",
						Value:      "SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK",
						TarianType: 7,
						LinuxType:  "int",
					},
					{
						Name:       "protocol",
						Value:      "IPPROTO_IP",
						TarianType: 7,
						LinuxType:  "int",
					},
				},
			},
		},
		{
			name:       "valid sys_bind_entry record parsing family AF_INET6",
			loadEvents: true,
			wantErr:    false,
			args: args{
				data: []byte{30, 0, 0, 0, 3, 49, 0, 0, 0, 34, 193, 57, 22, 40, 33, 0, 0, 4, 0, 71, 195, 17, 22, 40, 33, 0, 0, 199, 125, 41, 0, 199, 125, 41, 0, 72, 45, 1, 0, 199, 125, 41, 0, 199, 125, 41, 0, 72, 45, 1, 0, 24, 197, 143, 36, 193, 191, 143, 36, 246, 14, 0, 0, 0, 0, 0, 0, 1, 0, 0, 240, 0, 0, 0, 0, 252, 255, 255, 239, 0, 0, 0, 0, 71, 195, 17, 22, 239, 125, 41, 0, 250, 174, 10, 131, 89, 45, 1, 0, 98, 105, 110, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47, 104, 111, 109, 101, 47, 99, 114, 97, 118, 101, 108, 97, 64, 97, 112, 112, 115, 116, 101, 107, 99, 111, 114, 112, 46, 108, 111, 99, 97, 108, 47, 80, 114, 111, 106, 101, 99, 116, 115, 47, 68, 79, 85, 66, 76, 69, 47, 68, 69, 76, 69, 84, 69, 47, 68, 69, 76, 69, 84, 69, 47, 116, 97, 114, 105, 97, 110, 45, 100, 101, 116, 101, 99, 116, 111, 114, 47, 112, 107, 103, 47, 101, 66, 80, 70, 47, 99, 47, 98, 112, 102, 47, 110, 101, 116, 119, 111, 114, 107, 95, 98, 105, 110, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 105, 110, 117, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 67, 76, 80, 84, 68, 65, 76, 48, 54, 51, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 46, 49, 53, 46, 48, 45, 57, 55, 45, 103, 101, 110, 101, 114, 105, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 49, 48, 55, 126, 50, 48, 46, 48, 52, 46, 49, 45, 85, 98, 117, 110, 116, 117, 32, 83, 77, 80, 32, 70, 114, 105, 32, 70, 101, 98, 32, 57, 32, 49, 52, 58, 50, 48, 58, 49, 49, 32, 85, 84, 67, 32, 50, 48, 50, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 56, 54, 95, 54, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 110, 111, 110, 101, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 31, 144, 28, 0, 0, 0},
			},
			want: map[string]any{
				"eventId":             "sys_bind_entry",
				"timestamp":           uint64(36456055292194),
				"syscallId":           int32(49),
				"processor":           uint16(4),
				"threadStartTime":     uint64(36456052671303),
				"hostProcessId":       uint32(2719175),
				"hostThreadId":        uint32(2719175),
				"hostParentProcessId": uint32(77128),
				"processId":           uint32(2719175),
				"threadId":            uint32(2719175),
				"parentProcessId":     uint32(77128),
				"userId":              uint32(613401880),
				"groupId":             uint32(613400513),
				"cgroupId":            uint64(3830),
				"mountNamespace":      uint64(4026531841),
				"pidNamespace":        uint64(4026531836),
				"execId":              uint64(11678939866055495),
				"parentExecId":        uint64(331337450565370),
				"processName":         "bind",
				"directory":           "/home/cravela@appstekcorp.local/Projects/DOUBLE/DELETE/DELETE/tarian-detector/pkg/eBPF/c/bpf/network_bind",
				"sysname":             "Linux",
				"nodename":            "ACLPTDAL0631",
				"release":             "5.15.0-97-generic",
				"version":             "#107~20.04.1-Ubuntu SMP Fri Feb 9 14:20:11 UTC 2024",
				"machine":             "x86_64",
				"domainname":          "(none)",
				"context": []arg{
					{
						Name:       "fd",
						Value:      "3",
						TarianType: 7,
						LinuxType:  "int",
					},
					{
						Name: "umyaddr",
						Value: fmt.Sprintf("%+v", struct {
							Family  string
							Sa_addr string
							Sa_port uint16
						}{Family: "AF_INET6", Sa_addr: "::1", Sa_port: 8080}),
						TarianType: 14,
						LinuxType:  "struct sockaddr *",
					},
					{Name: "addrlen", Value: "28", TarianType: 7, LinuxType: "int"},
				},
			},
		},
		{
			name:       "valid sys_bind_entry record parsing family AF_INET",
			loadEvents: true,
			wantErr:    false,
			args: args{
				data: []byte{30, 0, 0, 0, 3, 49, 0, 0, 0, 176, 136, 54, 5, 54, 34, 0, 0, 6, 0, 114, 61, 18, 5, 54, 34, 0, 0, 157, 39, 17, 0, 157, 39, 17, 0, 72, 45, 1, 0, 157, 39, 17, 0, 157, 39, 17, 0, 72, 45, 1, 0, 24, 197, 143, 36, 193, 191, 143, 36, 246, 14, 0, 0, 0, 0, 0, 0, 1, 0, 0, 240, 0, 0, 0, 0, 252, 255, 255, 239, 0, 0, 0, 0, 114, 61, 18, 5, 191, 39, 17, 0, 250, 174, 10, 131, 89, 45, 1, 0, 98, 105, 110, 100, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47, 104, 111, 109, 101, 47, 99, 114, 97, 118, 101, 108, 97, 64, 97, 112, 112, 115, 116, 101, 107, 99, 111, 114, 112, 46, 108, 111, 99, 97, 108, 47, 80, 114, 111, 106, 101, 99, 116, 115, 47, 68, 79, 85, 66, 76, 69, 47, 68, 69, 76, 69, 84, 69, 47, 68, 69, 76, 69, 84, 69, 47, 116, 97, 114, 105, 97, 110, 45, 100, 101, 116, 101, 99, 116, 111, 114, 47, 112, 107, 103, 47, 101, 66, 80, 70, 47, 99, 47, 98, 112, 102, 47, 110, 101, 116, 119, 111, 114, 107, 95, 98, 105, 110, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 105, 110, 117, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 67, 76, 80, 84, 68, 65, 76, 48, 54, 51, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 46, 49, 53, 46, 48, 45, 57, 55, 45, 103, 101, 110, 101, 114, 105, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 49, 48, 55, 126, 50, 48, 46, 48, 52, 46, 49, 45, 85, 98, 117, 110, 116, 117, 32, 83, 77, 80, 32, 70, 114, 105, 32, 70, 101, 98, 32, 57, 32, 49, 52, 58, 50, 48, 58, 49, 49, 32, 85, 84, 67, 32, 50, 48, 50, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 56, 54, 95, 54, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 110, 111, 110, 101, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 2, 0, 0, 0, 0, 31, 144, 16, 0, 0, 0, 0, 0, 0, 0},
			},
			want: map[string]any{
				"eventId":             "sys_bind_entry",
				"timestamp":           uint64(37615411038384),
				"syscallId":           int32(49),
				"processor":           uint16(6),
				"threadStartTime":     uint64(37615408659826),
				"hostProcessId":       uint32(1124253),
				"hostThreadId":        uint32(1124253),
				"hostParentProcessId": uint32(77128),
				"processId":           uint32(1124253),
				"threadId":            uint32(1124253),
				"parentProcessId":     uint32(77128),
				"userId":              uint32(613401880),
				"groupId":             uint32(613400513),
				"cgroupId":            uint64(3830),
				"mountNamespace":      uint64(4026531841),
				"pidNamespace":        uint64(4026531836),
				"execId":              uint64(4828775981399410),
				"parentExecId":        uint64(331337450565370),
				"processName":         "bind4",
				"directory":           "/home/cravela@appstekcorp.local/Projects/DOUBLE/DELETE/DELETE/tarian-detector/pkg/eBPF/c/bpf/network_bind",
				"sysname":             "Linux",
				"nodename":            "ACLPTDAL0631",
				"release":             "5.15.0-97-generic",
				"version":             "#107~20.04.1-Ubuntu SMP Fri Feb 9 14:20:11 UTC 2024",
				"machine":             "x86_64",
				"domainname":          "(none)",
				"context": []arg{
					{
						Name:       "fd",
						Value:      "3",
						TarianType: 7,
						LinuxType:  "int",
					},
					{
						Name: "umyaddr",
						Value: fmt.Sprintf("%+v", struct {
							Family  string
							Sa_addr string
							Sa_port uint16
						}{Family: "AF_INET", Sa_addr: "0.0.0.0", Sa_port: 8080}),
						TarianType: 14,
						LinuxType:  "struct sockaddr *",
					},
					{Name: "addrlen", Value: "16", TarianType: 7, LinuxType: "int"},
				},
			},
		},
		{
			name:       "valid sys_bind_entry record parsing family AF_UNIX",
			loadEvents: true,
			wantErr:    false,
			args: args{
				data: []byte{30, 0, 0, 0, 3, 49, 0, 0, 0, 85, 21, 60, 167, 192, 34, 0, 0, 2, 0, 146, 158, 19, 167, 192, 34, 0, 0, 7, 172, 37, 0, 7, 172, 37, 0, 16, 221, 29, 0, 7, 172, 37, 0, 7, 172, 37, 0, 16, 221, 29, 0, 24, 197, 143, 36, 193, 191, 143, 36, 198, 31, 0, 0, 0, 0, 0, 0, 1, 0, 0, 240, 0, 0, 0, 0, 252, 255, 255, 239, 0, 0, 0, 0, 146, 158, 19, 167, 199, 174, 37, 0, 39, 14, 153, 126, 157, 255, 29, 0, 117, 110, 105, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 47, 104, 111, 109, 101, 47, 99, 114, 97, 118, 101, 108, 97, 64, 97, 112, 112, 115, 116, 101, 107, 99, 111, 114, 112, 46, 108, 111, 99, 97, 108, 47, 80, 114, 111, 106, 101, 99, 116, 115, 47, 68, 79, 85, 66, 76, 69, 47, 68, 69, 76, 69, 84, 69, 47, 68, 69, 76, 69, 84, 69, 47, 116, 97, 114, 105, 97, 110, 45, 100, 101, 116, 101, 99, 116, 111, 114, 47, 112, 107, 103, 47, 101, 66, 80, 70, 47, 99, 47, 98, 112, 102, 47, 110, 101, 116, 119, 111, 114, 107, 95, 98, 105, 110, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 105, 110, 117, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 67, 76, 80, 84, 68, 65, 76, 48, 54, 51, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 46, 49, 53, 46, 48, 45, 57, 55, 45, 103, 101, 110, 101, 114, 105, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 49, 48, 55, 126, 50, 48, 46, 48, 52, 46, 49, 45, 85, 98, 117, 110, 116, 117, 32, 83, 77, 80, 32, 70, 114, 105, 32, 70, 101, 98, 32, 57, 32, 49, 52, 58, 50, 48, 58, 49, 49, 32, 85, 84, 67, 32, 50, 48, 50, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 120, 56, 54, 95, 54, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 110, 111, 110, 101, 41, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1, 21, 0, 47, 116, 109, 112, 47, 109, 121, 95, 117, 110, 105, 120, 95, 115, 111, 99, 107, 101, 116, 50, 0, 110, 0, 0, 0, 0, 0, 0},
			},
			want: map[string]any{
				"eventId":             "sys_bind_entry",
				"timestamp":           uint64(38210834797909),
				"syscallId":           int32(49),
				"processor":           uint16(2),
				"threadStartTime":     uint64(38210832146066),
				"hostProcessId":       uint32(2468871),
				"hostThreadId":        uint32(2468871),
				"hostParentProcessId": uint32(1957136),
				"processId":           uint32(2468871),
				"threadId":            uint32(2468871),
				"parentProcessId":     uint32(1957136),
				"userId":              uint32(613401880),
				"groupId":             uint32(613400513),
				"cgroupId":            uint64(8134),
				"mountNamespace":      uint64(4026531841),
				"pidNamespace":        uint64(4026531836),
				"execId":              uint64(10606746663100050),
				"parentExecId":        uint64(8443826223517223),
				"processName":         "unix",
				"directory":           "/home/cravela@appstekcorp.local/Projects/DOUBLE/DELETE/DELETE/tarian-detector/pkg/eBPF/c/bpf/network_bind",
				"sysname":             "Linux",
				"nodename":            "ACLPTDAL0631",
				"release":             "5.15.0-97-generic",
				"version":             "#107~20.04.1-Ubuntu SMP Fri Feb 9 14:20:11 UTC 2024",
				"machine":             "x86_64",
				"domainname":          "(none)",
				"context": []arg{
					{
						Name:       "fd",
						Value:      "3",
						TarianType: 7,
						LinuxType:  "int",
					},
					{
						Name: "umyaddr",
						Value: fmt.Sprintf("%+v", struct {
							Family   string
							Sun_path string
						}{Family: "AF_UNIX", Sun_path: "/tmp/my_unix_socket2"}),
						TarianType: 14,
						LinuxType:  "struct sockaddr *",
					},
					{Name: "addrlen", Value: "110", TarianType: 7, LinuxType: "int"},
				},
			},
		},
	}

	for _, tt := range tests {
		if tt.loadEvents {
			LoadTarianEvents()
		}

		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseByteArray(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseByteArray() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseByteArray() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestByteStream_parseParams tests the parseParams function.
func TestByteStream_parseParams(t *testing.T) {
	type args struct {
		event TarianEvent
	}
	tests := []struct {
		name    string
		fields  ByteStream
		args    args
		want    []arg
		wantErr bool
	}{
		{
			name:    "empty tarian event",
			wantErr: true,
		}, {
			name: "break bs.position >= len(bs.data)",
			fields: ByteStream{
				position: 0,
				nparams:  2,
			},
			args: args{
				event: TarianEvent{
					name:      "test",
					syscallId: 0,
					eventSize: 783,
					params: []Param{
						Param{}, Param{},
					},
				},
			},
			want:    []arg{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := &ByteStream{
				data:     tt.fields.data,
				position: tt.fields.position,
				nparams:  tt.fields.nparams,
			}
			got, err := bs.parseParams(tt.args.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("ByteStream.parseParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ByteStream.parseParams() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestByteStream_parseParam tests the parseParam function.
func TestByteStream_parseParam(t *testing.T) {
	type args struct {
		p Param
	}
	tests := []struct {
		name    string
		fields  ByteStream
		args    args
		want    arg
		wantErr bool
	}{
		{
			name: "call Uint8",
			fields: ByteStream{
				data:     []byte{1, 2, 3},
				position: 0,
				nparams:  2,
			},
			args: args{
				p: Param{
					name:      "test",
					paramType: TDT_U8,
					linuxType: "uint8_t",
				},
			},
			want: arg{
				Name:       "test",
				Value:      "1",
				TarianType: 1,
				LinuxType:  "uint8_t",
			},
			wantErr: false,
		},
		{
			name: "call Uint16",
			fields: ByteStream{
				data:     []byte{1, 2, 3},
				position: 0,
				nparams:  2,
			},
			args: args{
				p: Param{
					name:      "test",
					paramType: TDT_U16,
					linuxType: "uint16_t",
				},
			},
			want: arg{
				Name:       "test",
				Value:      "513",
				TarianType: 2,
				LinuxType:  "uint16_t",
			},
			wantErr: false,
		},
		{
			name: "call Uint64",
			fields: ByteStream{
				data:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
				position: 0,
				nparams:  2,
			},
			args: args{
				p: Param{
					name:      "test",
					paramType: TDT_U64,
					linuxType: "uint64_t",
				},
			},
			want: arg{
				Name:       "test",
				Value:      "578437695752307201",
				TarianType: 4,
				LinuxType:  "uint64_t",
			},
			wantErr: false,
		},
		{
			name: "call Int8",
			fields: ByteStream{
				data:     []byte{1, 2, 3},
				position: 0,
				nparams:  2,
			},
			args: args{
				p: Param{
					name:      "test",
					paramType: TDT_S8,
					linuxType: "int8_t",
				},
			},
			want:    arg{"test", "1", 5, "int8_t"},
			wantErr: false,
		},
		{
			name: "call Int16",
			fields: ByteStream{
				data:     []byte{1, 2, 3},
				position: 0,
				nparams:  2,
			},
			args: args{
				p: Param{
					name:      "test",
					paramType: TDT_S16,
					linuxType: "int16_t",
				},
			},
			want:    arg{"test", "513", 6, "int16_t"},
			wantErr: false,
		},
		{
			name: "call Int64",
			fields: ByteStream{
				data:     []byte{1, 2, 3, 4, 5, 6, 7, 8},
				position: 0,
				nparams:  2,
			},
			args: args{
				p: Param{
					name:      "test",
					paramType: TDT_S64,
					linuxType: "int64_t",
				},
			},
			want:    arg{"test", "578437695752307201", 8, "int64_t"},
			wantErr: false,
		},
		{
			name: "call String",
			fields: ByteStream{
				data:     []byte{4, 0, 65, 66, 67, 68},
				position: 0,
				nparams:  2,
			},
			args: args{
				p: Param{
					name:      "test",
					paramType: TDT_STR,
					linuxType: "string",
				},
			},
			want:    arg{"test", "ABCD", 10, "string"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := &ByteStream{
				data:     tt.fields.data,
				position: tt.fields.position,
				nparams:  tt.fields.nparams,
			}
			got, err := bs.parseParam(tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("ByteStream.parseParam() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ByteStream.parseParam() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestByteStream_parseString tests the parseString function.
func TestByteStream_parseString(t *testing.T) {
	type fields struct {
		data     []byte
		position int
		nparams  uint8
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name: "invalid values",
			fields: fields{
				data:     []byte{1},
				position: 0,
				nparams:  2,
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := &ByteStream{
				data:     tt.fields.data,
				position: tt.fields.position,
				nparams:  tt.fields.nparams,
			}
			got, err := bs.parseString()
			if (err != nil) != tt.wantErr {
				t.Errorf("ByteStream.parseString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ByteStream.parseString() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestByteStream_parseRawArray tests the parseRawArray function.
func TestByteStream_parseRawArray(t *testing.T) {
	type fields struct {
		data     []byte
		position int
		nparams  uint8
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			name: "invalid values",
			fields: fields{
				data:     []byte{1},
				position: 0,
				nparams:  2,
			},
			want:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := &ByteStream{
				data:     tt.fields.data,
				position: tt.fields.position,
				nparams:  tt.fields.nparams,
			}
			got, err := bs.parseRawArray()
			if (err != nil) != tt.wantErr {
				t.Errorf("ByteStream.parseRawArray() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ByteStream.parseRawArray() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestByteStream_parseSocketAddress tests the parseSocketAddress function.
func TestByteStream_parseSocketAddress(t *testing.T) {
	type fields struct {
		data     []byte
		position int
		nparams  uint8
	}
	tests := []struct {
		name    string
		fields  fields
		want    any
		wantErr bool
	}{
		{
			name: "invalid values",
			fields: fields{
				data:     []byte{},
				position: 0,
				nparams:  2,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "unhandled case",
			fields: fields{
				data:     []byte{0},
				position: 0,
				nparams:  2,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "AF_INET Uint16 error",
			fields: fields{
				data:     []byte{2, 8, 9, 0, 3, 1},
				position: 0,
				nparams:  2,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "AF_INET6 Uint16 error",
			fields: fields{
				data:     []byte{10, 8, 9, 0, 3, 1},
				position: 0,
				nparams:  2,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "AF_UNIX Uint16 error",
			fields: fields{
				data:     []byte{1, 8},
				position: 0,
				nparams:  2,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := &ByteStream{
				data:     tt.fields.data,
				position: tt.fields.position,
				nparams:  tt.fields.nparams,
			}
			got, err := bs.parseSocketAddress()
			if (err != nil) != tt.wantErr {
				t.Errorf("ByteStream.parseSocketAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ByteStream.parseSocketAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}
