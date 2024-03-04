// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TestHookInfo tests the HookInfo type
func TestHookInfo(t *testing.T) {
	tests := []struct {
		name string
		hi   *HookInfo
		want string
	}{
		{
			name: "Tracepoint",
			hi:   NewHookInfo().Tracepoint("group", "name"),
			want: "Tracepoint",
		},
		{
			name: "Tracepoint with options",
			hi:   NewHookInfo().Tracepoint("group", "name", nil),
			want: "Tracepoint",
		},
		{
			name: "RawTracepoint",
			hi:   NewHookInfo().RawTracepoint(link.RawTracepointOptions{}),
			want: "RawTracepoint",
		},
		{
			name: "Kprobe",
			hi:   NewHookInfo().Kprobe("name"),
			want: "Kprobe",
		},
		{
			name: "Kprobe with options",
			hi:   NewHookInfo().Kprobe("name", nil),
			want: "Kprobe",
		},
		{
			name: "Kretprobe",
			hi:   NewHookInfo().Kretprobe("name"),
			want: "Kretprobe",
		},
		{
			name: "Kretprobe with options",
			hi:   NewHookInfo().Kretprobe("name", nil),
			want: "Kretprobe",
		},
		{
			name: "Cgroup",
			hi:   NewHookInfo().Cgroup(link.CgroupOptions{}),
			want: "Cgroup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hi.GetHookType().String(); got != tt.want {
				t.Errorf("HookInfo.GetHookType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHookInfo_AttachProbe tests the AttachProbe function
func TestHookInfo_AttachProbe(t *testing.T) {
	// Mock program
	prog := &ebpf.Program{}

	tests := []struct {
		name    string
		hi      *HookInfo
		wantErr bool
	}{
		{
			name:    "Tracepoint with missing name",
			hi:      NewHookInfo().Tracepoint("", "name"),
			wantErr: true,
		},
		{
			name:    "Tracepoint with missing group",
			hi:      NewHookInfo().Tracepoint("group", ""),
			wantErr: true,
		},
		{
			name: "Tracepoint with wrong options type",
			hi: func() *HookInfo {
				hi := NewHookInfo().Tracepoint("group", "test")
				hi.opts = link.KprobeOptions{}
				return hi
			}(),
			wantErr: true,
		},
		{
			name:    "Tracepoint",
			hi:      NewHookInfo().Tracepoint("group", "test"),
			wantErr: true,
		},
		{
			name: "RawTracepoint with wrong options type",
			hi: func() *HookInfo {
				hi := NewHookInfo()
				hi.hookType = RawTracepoint
				hi.opts = link.KprobeOptions{}
				return hi
			}(),
			wantErr: true,
		},
		{
			name:    "RawTracepoint",
			hi:      NewHookInfo().RawTracepoint(link.RawTracepointOptions{Name: "__x64_sys_printk", Program: prog}),
			wantErr: true,
		},
		{
			name:    "Kprobe with missing name",
			hi:      NewHookInfo().Kprobe(""),
			wantErr: true,
		},
		{
			name:    "Kretprobe with missing name",
			hi:      NewHookInfo().Kretprobe(""),
			wantErr: true,
		},
		{
			name: "Kretprobe with wrong options type",
			hi: func() *HookInfo {
				hi := NewHookInfo().Kretprobe("vprintk")
				hi.opts = link.TracepointOptions{}

				return hi
			}(),
			wantErr: true,
		},
		{
			name:    "Kretprobe",
			hi:      NewHookInfo().Kretprobe("vprintk"),
			wantErr: true,
		},
		{
			name: "Cgroup with wrong options type",
			hi: func() *HookInfo {
				hi := NewHookInfo()
				hi.hookType = Cgroup
				hi.opts = link.KprobeOptions{}
				return hi
			}(),
			wantErr: true,
		},
		{
			name:    "Cgroup",
			hi:      NewHookInfo().Cgroup(link.CgroupOptions{Path: "", Attach: 0, Program: prog}),
			wantErr: true,
		},
		{
			name:    "Invalid HookInfoType",
			hi:      &HookInfo{hookType: HookInfoType(999)}, // An unknown HookInfoType
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.hi.AttachProbe(prog)
			if (err != nil) != tt.wantErr {
				t.Errorf("HookInfo.AttachProbe() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestHookInfo_GetHookName tests the GetHookName function
func TestHookInfo_GetHookName(t *testing.T) {
	tests := []struct {
		name string
		hi   *HookInfo
		want string
	}{
		{
			name: "Tracepoint",
			hi:   NewHookInfo().Tracepoint("group", "name"),
			want: "name",
		},
		{
			name: "Kprobe",
			hi:   NewHookInfo().Kprobe("name"),
			want: "name",
		},
		{
			name: "Kretprobe",
			hi:   NewHookInfo().Kretprobe("name"),
			want: "name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hi.GetHookName(); got != tt.want {
				t.Errorf("HookInfo.GetHookName() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHookInfo_GetHookGroup tests the GetHookGroup function
func TestHookInfo_GetHookGroup(t *testing.T) {
	tests := []struct {
		name string
		hi   *HookInfo
		want string
	}{
		{
			name: "Tracepoint",
			hi:   NewHookInfo().Tracepoint("group", "name"),
			want: "group",
		},
		{
			name: "Kprobe",
			hi:   NewHookInfo().Kprobe("name"),
			want: "",
		},
		{
			name: "Kretprobe",
			hi:   NewHookInfo().Kretprobe("name"),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hi.GetHookGroup(); got != tt.want {
				t.Errorf("HookInfo.GetHookGroup() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHookInfo_GetOptions tests the GetOptions function
func TestHookInfo_GetOptions(t *testing.T) {
	tests := []struct {
		name string
		hi   *HookInfo
		want any
	}{
		{
			name: "Tracepoint",
			hi:   NewHookInfo().Tracepoint("group", "name"),
			want: &link.TracepointOptions{},
		},
		{
			name: "RawTracepoint",
			hi:   NewHookInfo().RawTracepoint(link.RawTracepointOptions{}),
			want: link.RawTracepointOptions{},
		},
		{
			name: "Kprobe",
			hi:   NewHookInfo().Kprobe("name"),
			want: &link.KprobeOptions{},
		},
		{
			name: "Kretprobe",
			hi:   NewHookInfo().Kretprobe("name"),
			want: &link.KprobeOptions{},
		},
		{
			name: "Cgroup",
			hi:   NewHookInfo().Cgroup(link.CgroupOptions{}),
			want: link.CgroupOptions{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.hi.GetOptions()
			if reflect.TypeOf(got) != reflect.TypeOf(tt.want) {
				t.Errorf("HookInfo.GetOptions() = %T, want %T", got, tt.want)
			}
		})
	}
}

// TestHookInfoType_String tests the String function
func TestHookInfoType_String(t *testing.T) {
	tests := []struct {
		name string
		hit  HookInfoType
		want string
	}{
		{
			name: "Tracepoint",
			hit:  Tracepoint,
			want: "Tracepoint",
		},
		{
			name: "RawTracepoint",
			hit:  RawTracepoint,
			want: "RawTracepoint",
		},
		{
			name: "Kprobe",
			hit:  Kprobe,
			want: "Kprobe",
		},
		{
			name: "Kretprobe",
			hit:  Kretprobe,
			want: "Kretprobe",
		},
		{
			name: "Cgroup",
			hit:  Cgroup,
			want: "Cgroup",
		},
		{
			name: "Unknown",
			hit:  HookInfoType(999), // An unknown HookInfoType
			want: "unknown HookInfoType(999)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.hit.String(); got != tt.want {
				t.Errorf("HookInfoType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_detachProbe tests the detachProbe function
func Test_detachProbe(t *testing.T) {
	prog := dummy_kprobe_prog(t)
	l, _ := link.Kprobe("vprintk", prog, nil)

	type args struct {
		l link.Link
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "invalid link",
			args:    args{l: l},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := detachProbe(tt.args.l); (err != nil) != tt.wantErr {
				t.Errorf("detachProbe() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_detachProbes(t *testing.T) {
	prog := dummy_kprobe_prog(t)
	l, _ := link.Kprobe("vprintk", prog, nil)

	type args struct {
		lns []link.Link
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "link",
			args:    args{lns: []link.Link{l}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := detachProbes(tt.args.lns); (err != nil) != tt.wantErr {
				t.Errorf("detachProbes() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
