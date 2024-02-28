// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"os"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

func dummy_perf_map(t *testing.T) *ebpf.Map {
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
	})
	if err != nil {
		t.Fatal("HERE--->", err)
	}

	t.Cleanup(func() { events.Close() })
	return events
}

// TestNewModule tests the creation of a new Module object
func TestNewModule(t *testing.T) {
	type args struct {
		n string
	}
	tests := []struct {
		name string
		args args
		want *Module
	}{
		{
			name: "default values",
			args: args{
				n: "test",
			},
			want: &Module{
				name:     "test",
				ebpfMap:  nil,
				programs: make([]*ProgramInfo, 0),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewModule(tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewModule() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestModule_AddProgram tests the AddProgram function
func TestModule_AddProgram(t *testing.T) {
	type fields struct {
		name     string
		programs []*ProgramInfo
		ebpfMap  *MapInfo
	}
	type args struct {
		prog *ProgramInfo
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int
	}{
		{
			name: "valid values",
			fields: fields{
				name:     "test",
				programs: make([]*ProgramInfo, 0),
				ebpfMap:  nil,
			},
			args: args{
				prog: &ProgramInfo{
					name:         &ebpf.Program{},
					hook:         &HookInfo{},
					shouldAttach: true,
				},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Module{
				name:     tt.fields.name,
				programs: tt.fields.programs,
				ebpfMap:  tt.fields.ebpfMap,
			}

			m.AddProgram(tt.args.prog)

			if len(m.programs) != tt.want {
				t.Errorf("Module.AddProgram() = %v, want %v", len(m.programs), tt.want)
			}
		})
	}
}

// TestModule_Map tests the Map function
func TestModule_Map(t *testing.T) {
	type fields struct {
		name     string
		programs []*ProgramInfo
		ebpfMap  *MapInfo
	}
	type args struct {
		mp *MapInfo
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *MapInfo
	}{
		{
			name: "valid default values",
			fields: fields{
				name:     "test",
				programs: make([]*ProgramInfo, 0),
				ebpfMap:  nil,
			},
			args: args{
				mp: &MapInfo{},
			},
			want: &MapInfo{},
		},
		{
			name: "nil values",
			fields: fields{
				name:     "test",
				programs: make([]*ProgramInfo, 0),
				ebpfMap:  nil,
			},
			args: args{
				mp: nil,
			},
			want: nil,
		}, {
			name: "valid values",
			fields: fields{
				name:     "test",
				programs: make([]*ProgramInfo, 0),
				ebpfMap:  nil,
			},
			args: args{
				mp: NewRingBuf(nil),
			},
			want: &MapInfo{
				mapType:      RingBuffer,
				bpfMap:       nil,
				innerMapType: -1,
				bufferSize:   0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Module{
				name:     tt.fields.name,
				programs: tt.fields.programs,
				ebpfMap:  tt.fields.ebpfMap,
			}
			m.Map(tt.args.mp)

			if !reflect.DeepEqual(m.ebpfMap, tt.want) {
				t.Errorf("Module.Map() = %v, want %v", m.ebpfMap, tt.want)
			}
		})
	}
}

// TestModule_GetName tests the GetName function
func TestModule_GetName(t *testing.T) {
	type fields struct {
		name     string
		programs []*ProgramInfo
		ebpfMap  *MapInfo
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "valid values",
			fields: fields{
				name:     "test",
				programs: make([]*ProgramInfo, 0),
				ebpfMap:  nil,
			},
			want: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Module{
				name:     tt.fields.name,
				programs: tt.fields.programs,
				ebpfMap:  tt.fields.ebpfMap,
			}
			if got := m.GetName(); got != tt.want {
				t.Errorf("Module.GetName() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestModule_GetPrograms tests the GetPrograms function
func TestModule_GetPrograms(t *testing.T) {
	type fields struct {
		name     string
		programs []*ProgramInfo
		ebpfMap  *MapInfo
	}
	tests := []struct {
		name   string
		fields fields
		want   []*ProgramInfo
	}{
		{
			name: "valid values",
			fields: fields{
				name:     "test",
				programs: make([]*ProgramInfo, 0),
				ebpfMap:  nil,
			},
			want: make([]*ProgramInfo, 0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Module{
				name:     tt.fields.name,
				programs: tt.fields.programs,
				ebpfMap:  tt.fields.ebpfMap,
			}
			if got := m.GetPrograms(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Module.GetPrograms() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestModule_GetMap tests the GetMap function
func TestModule_GetMap(t *testing.T) {
	type fields struct {
		name     string
		programs []*ProgramInfo
		ebpfMap  *MapInfo
	}
	tests := []struct {
		name   string
		fields fields
		want   *MapInfo
	}{
		{
			name: "valid values",
			fields: fields{
				name:     "test",
				programs: make([]*ProgramInfo, 0),
				ebpfMap:  NewPerfEvent(nil),
			},
			want: &MapInfo{
				mapType:      PerfEventArray,
				bpfMap:       nil,
				bufferSize:   os.Getpagesize(),
				innerMapType: -1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Module{
				name:     tt.fields.name,
				programs: tt.fields.programs,
				ebpfMap:  tt.fields.ebpfMap,
			}
			if got := m.GetMap(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Module.GetMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestModule_Prepare tests the Prepare function
func TestModule_Prepare(t *testing.T) {
	mapP := dummy_perf_map(t)
	prog := dummy_kprobe_prog(t)

	type fields struct {
		name     string
		programs []*ProgramInfo
		ebpfMap  *MapInfo
	}
	tests := []struct {
		name    string
		fields  fields
		want    *Handler
		wantErr bool
	}{
		{
			name: "valid values with nil program and map",
			fields: fields{
				name:     "test",
				programs: make([]*ProgramInfo, 0),
				ebpfMap:  nil,
			},
			want: &Handler{
				name: "test",
			},

			wantErr: false,
		},
		{
			name: "valid values with dummy program and map",
			fields: fields{
				name: "test",
				programs: []*ProgramInfo{
					NewProgram(prog, NewHookInfo().Kprobe("vprintk")),
				},
				ebpfMap: NewPerfEvent(mapP),
			},
			want: &Handler{
				name: "test",
				probeLinks: []link.Link{
					func() link.Link {
						l, _ := link.Kprobe("vprintk", prog, nil)
						return l
					}(),
				},
				mapReaders: []any{
					func() *perf.Reader {
						r, _ := perf.NewReader(mapP, os.Getpagesize())
						return r
					}(),
				},
			},
			wantErr: false,
		},
		{
			name: "disabled program",
			fields: fields{
				name: "test",
				programs: []*ProgramInfo{
					NewProgram(prog, NewHookInfo().Kprobe("vprintk")).Disable(),
				},
				ebpfMap: nil,
			},
			want: &Handler{
				name: "test",
			},

			wantErr: false,
		},
		{
			name: "nil ebpf prog",
			fields: fields{
				name: "test",
				programs: []*ProgramInfo{
					NewProgram(prog, NewHookInfo().Kprobe("")),
				},
				ebpfMap: nil,
			},

			wantErr: true,
		},
		{
			name: "wrong map type",
			fields: fields{
				name: "test",
				ebpfMap: &MapInfo{
					mapType: -1,
				},
			},

			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Module{
				name:     tt.fields.name,
				programs: tt.fields.programs,
				ebpfMap:  tt.fields.ebpfMap,
			}
			got, err := m.Prepare()
			if (err != nil) != tt.wantErr {
				t.Errorf("Module.Prepare() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if (got == nil) && (tt.wantErr) {
				return
			}

			if got.name != tt.want.name {
				t.Errorf("Module.Prepare().name = %v, want %v", got.name, tt.want.name)
			}

			if len(got.mapReaders) != len(tt.want.mapReaders) {
				t.Errorf("Module.Prepare().mapReaders = %v, want %v", got.mapReaders, tt.want.mapReaders)
			}

			if len(got.probeLinks) != len(tt.want.probeLinks) {
				t.Errorf("Module.Prepare().probeLinks = %v, want %v", got.probeLinks, tt.want.probeLinks)
			}
		})
	}
}
