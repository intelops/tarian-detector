// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

func dummy_kprobe_prog(t *testing.T) *ebpf.Program {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.Kprobe,
		AttachType: 0,
		AttachTo:   "",
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		t.Errorf("dummy_kprobe_prog: %v", err)
	}

	return prog
}

// TestNewProgram tests the creation of a new ProgramInfo object
func TestNewProgram(t *testing.T) {
	type args struct {
		n *ebpf.Program
		h *HookInfo
	}
	tests := []struct {
		name string
		args args
		want *ProgramInfo
	}{
		{
			name: "valid values",
			args: args{
				n: &ebpf.Program{},
				h: &HookInfo{},
			},
			want: &ProgramInfo{
				name:         &ebpf.Program{},
				hook:         &HookInfo{},
				shouldAttach: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewProgram(tt.args.n, tt.args.h); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewProgram() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestProgramInfo_Enable tests the Enable function
func TestProgramInfo_Enable(t *testing.T) {
	type fields struct {
		name         *ebpf.Program
		hook         *HookInfo
		shouldAttach bool
	}
	tests := []struct {
		name   string
		fields fields
		want   *ProgramInfo
	}{
		{
			name: "valid values with false",
			fields: fields{
				name:         &ebpf.Program{},
				hook:         &HookInfo{},
				shouldAttach: false,
			},
			want: &ProgramInfo{
				name:         &ebpf.Program{},
				hook:         &HookInfo{},
				shouldAttach: true,
			},
		},
		{
			name: "valid values with true",
			fields: fields{
				name:         &ebpf.Program{},
				hook:         &HookInfo{},
				shouldAttach: true,
			},
			want: &ProgramInfo{
				name:         &ebpf.Program{},
				hook:         &HookInfo{},
				shouldAttach: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pi := &ProgramInfo{
				name:         tt.fields.name,
				hook:         tt.fields.hook,
				shouldAttach: tt.fields.shouldAttach,
			}
			if got := pi.Enable(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProgramInfo.Enable() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestProgramInfo_Disable tests the Disable function
func TestProgramInfo_Disable(t *testing.T) {
	type fields struct {
		name         *ebpf.Program
		hook         *HookInfo
		shouldAttach bool
	}
	tests := []struct {
		name   string
		fields fields
		want   *ProgramInfo
	}{
		{
			name: "valid values with true",
			fields: fields{
				name:         &ebpf.Program{},
				hook:         &HookInfo{},
				shouldAttach: true,
			},
			want: &ProgramInfo{
				name:         &ebpf.Program{},
				hook:         &HookInfo{},
				shouldAttach: false,
			},
		},
		{
			name: "valid values with false",
			fields: fields{
				name:         &ebpf.Program{},
				hook:         &HookInfo{},
				shouldAttach: false,
			},
			want: &ProgramInfo{
				name:         &ebpf.Program{},
				hook:         &HookInfo{},
				shouldAttach: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pi := &ProgramInfo{
				name:         tt.fields.name,
				hook:         tt.fields.hook,
				shouldAttach: tt.fields.shouldAttach,
			}
			if got := pi.Disable(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProgramInfo.Disable() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestProgramInfo_GetHook tests the GetHook function
func TestProgramInfo_GetHook(t *testing.T) {
	type fields struct {
		name         *ebpf.Program
		hook         *HookInfo
		shouldAttach bool
	}
	tests := []struct {
		name   string
		fields fields
		want   *HookInfo
	}{
		{
			name: "valid values",
			fields: fields{
				name:         &ebpf.Program{},
				hook:         NewHookInfo().Kprobe("test"),
				shouldAttach: true,
			},
			want: &HookInfo{
				name:     "test",
				group:    "",
				opts:     &link.KprobeOptions{},
				hookType: 2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pi := &ProgramInfo{
				name:         tt.fields.name,
				hook:         tt.fields.hook,
				shouldAttach: tt.fields.shouldAttach,
			}
			if got := pi.GetHook(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProgramInfo.GetHook() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestProgramInfo_GetName tests the GetName function
func TestProgramInfo_GetName(t *testing.T) {
	prog := dummy_kprobe_prog(t)

	type fields struct {
		name         *ebpf.Program
		hook         *HookInfo
		shouldAttach bool
	}
	tests := []struct {
		name   string
		fields fields
		want   *ebpf.Program
	}{
		{
			name: "valid nil values",
			fields: fields{
				name: &ebpf.Program{},
			},
			want: &ebpf.Program{},
		},
		{
			name: "valid values",
			fields: fields{
				name: prog,
			},
			want: prog,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pi := &ProgramInfo{
				name:         tt.fields.name,
				hook:         tt.fields.hook,
				shouldAttach: tt.fields.shouldAttach,
			}
			if got := pi.GetName(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ProgramInfo.GetName() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestProgramInfo_GetShouldAttach tests the GetShouldAttach function
func TestProgramInfo_GetShouldAttach(t *testing.T) {
	type fields struct {
		name         *ebpf.Program
		hook         *HookInfo
		shouldAttach bool
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "valid values with true",
			fields: fields{
				shouldAttach: true,
			},
			want: true,
		},
		{
			name: "valid values with false",
			fields: fields{
				shouldAttach: false,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pi := &ProgramInfo{
				name:         tt.fields.name,
				hook:         tt.fields.hook,
				shouldAttach: tt.fields.shouldAttach,
			}
			if got := pi.GetShouldAttach(); got != tt.want {
				t.Errorf("ProgramInfo.GetShouldAttach() = %v, want %v", got, tt.want)
			}
		})
	}
}
