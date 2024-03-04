// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package ebpf

import (
	"os"
	"reflect"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// TestHandler_GetName tests the GetName function
func TestHandler_GetName(t *testing.T) {
	type fields struct {
		name       string
		mapReaders []any
		probeLinks []link.Link
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "valid values",
			fields: fields{
				name:       "test",
				mapReaders: make([]any, 0),
				probeLinks: make([]link.Link, 0),
			},
			want: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{
				name:       tt.fields.name,
				mapReaders: tt.fields.mapReaders,
				probeLinks: tt.fields.probeLinks,
			}
			if got := h.GetName(); got != tt.want {
				t.Errorf("Handler.GetName() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHandler_GetMapReaders tests the GetMapReaders function
func TestHandler_GetMapReaders(t *testing.T) {
	type fields struct {
		name       string
		mapReaders []any
		probeLinks []link.Link
	}
	tests := []struct {
		name   string
		fields fields
		want   []any
	}{
		{
			name: "valid values",
			fields: fields{
				name:       "test",
				mapReaders: make([]any, 0),
				probeLinks: make([]link.Link, 0),
			},
			want: make([]any, 0),
		},
		{
			name: "nil values",
			fields: fields{
				name:       "test",
				mapReaders: nil,
				probeLinks: nil,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{
				name:       tt.fields.name,
				mapReaders: tt.fields.mapReaders,
				probeLinks: tt.fields.probeLinks,
			}
			if got := h.GetMapReaders(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Handler.GetMapReaders() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHandler_GetProbeLinks tests the GetProbeLinks function
func TestHandler_GetProbeLinks(t *testing.T) {
	type fields struct {
		name       string
		mapReaders []any
		probeLinks []link.Link
	}
	tests := []struct {
		name   string
		fields fields
		want   []link.Link
	}{
		{
			name: "valid values",
			fields: fields{
				name:       "test",
				mapReaders: make([]any, 0),
				probeLinks: make([]link.Link, 0),
			},
			want: make([]link.Link, 0),
		},
		{
			name: "nil values",
			fields: fields{
				name:       "test",
				mapReaders: nil,
				probeLinks: nil,
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{
				name:       tt.fields.name,
				mapReaders: tt.fields.mapReaders,
				probeLinks: tt.fields.probeLinks,
			}
			if got := h.GetProbeLinks(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Handler.GetProbeLinks() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHandler_Count tests the Count function
func TestHandler_Count(t *testing.T) {
	prog := dummy_kprobe_prog(t)
	l, _ := link.Kprobe("vprintk", prog, nil)

	type fields struct {
		name       string
		mapReaders []any
		probeLinks []link.Link
	}
	tests := []struct {
		name   string
		fields fields
		want   int
	}{
		{
			name: "valid values",
			fields: fields{
				name:       "test",
				mapReaders: make([]any, 0),
				probeLinks: make([]link.Link, 0),
			},
			want: 0,
		},
		{
			name: "add an item to the probelink",
			fields: fields{
				name:       "test",
				mapReaders: nil,
				probeLinks: []link.Link{l, l, l},
			},
			want: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{
				name:       tt.fields.name,
				mapReaders: tt.fields.mapReaders,
				probeLinks: tt.fields.probeLinks,
			}
			if got := h.Count(); got != tt.want {
				t.Errorf("Handler.Count() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHandler_ReadAsInterface tests the ReadAsInterface function
func TestHandler_ReadAsInterface(t *testing.T) {
	mapP := dummy_perf_map(t)

	type fields struct {
		name       string
		mapReaders []any
		probeLinks []link.Link
	}
	tests := []struct {
		name    string
		fields  fields
		want    int
		wantErr bool
	}{
		{
			name: "valid values",
			fields: fields{
				name:       "test",
				mapReaders: make([]any, 0),
				probeLinks: make([]link.Link, 0),
			},
			want:    0,
			wantErr: false,
		},
		{
			name: "invalid values",
			fields: fields{
				name: "test",
				mapReaders: []any{
					func() *perf.Reader {
						r, _ := perf.NewReader(mapP, os.Getpagesize())
						return r
					}(),
				},
				probeLinks: make([]link.Link, 0),
			},
			want:    1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{
				name:       tt.fields.name,
				mapReaders: tt.fields.mapReaders,
				probeLinks: tt.fields.probeLinks,
			}
			got, err := h.ReadAsInterface()
			if (err != nil) != tt.wantErr {
				t.Errorf("Handler.ReadAsInterface() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if len(got) != tt.want {
				t.Errorf("Handler.ReadAsInterface() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestHandler_Close tests the Close function
func TestHandler_Close(t *testing.T) {
	type fields struct {
		name       string
		mapReaders []any
		probeLinks []link.Link
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "valid values",
			fields: fields{
				name:       "test",
				mapReaders: make([]any, 0),
				probeLinks: make([]link.Link, 0),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Handler{
				name:       tt.fields.name,
				mapReaders: tt.fields.mapReaders,
				probeLinks: tt.fields.probeLinks,
			}
			if err := h.Close(); (err != nil) != tt.wantErr {
				t.Errorf("Handler.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
