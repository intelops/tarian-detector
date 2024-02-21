// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package utils

import (
	"fmt"
	"os"
	"testing"
)

type args struct {
	major any
	minor any
	patch any
}

func (a *args) setup() {
	os.Setenv("LINUX_VERSION_MAJOR", fmt.Sprintf("%v", a.major))
	os.Setenv("LINUX_VERSION_MINOR", fmt.Sprintf("%v", a.minor))
	os.Setenv("LINUX_VERSION_PATCH", fmt.Sprintf("%v", a.patch))
}

func (a *args) teardown() {
	os.Unsetenv("LINUX_VERSION_MAJOR")
	os.Unsetenv("LINUX_VERSION_MINOR")
	os.Unsetenv("LINUX_VERSION_PATCH")
}

// TestKernelVersion is a Go function for testing the KernelVersion function.
func TestKernelVersion(t *testing.T) {
	tests := []struct {
		name string
		args args
		want int
	}{{
		name: "valid values",
		args: args{
			major: 5,
			minor: 10,
			patch: 15,
		},
		want: 330255,
	}, {
		name: "zero values",
		args: args{
			major: 0,
			minor: 0,
			patch: 0,
		},
		want: 0,
	}, {
		name: "patch greater than 255",
		args: args{
			major: 0,
			minor: 0,
			patch: 256,
		},
		want: 255,
	}, {
		name: "",
		args: args{
			major: 4,
			minor: 20,
			patch: 300,
		},
		want: 267519,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KernelVersion(tt.args.major.(int), tt.args.minor.(int), tt.args.patch.(int)); got != tt.want {
				t.Errorf("KernelVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCurrentKernelVersion is a Go function for testing the CurrentKernelVersion function.
func TestCurrentKernelVersion(t *testing.T) {
	tests := []struct {
		name    string
		args    *args
		want    int
		wantErr bool
	}{
		{
			name: "valid values",
			args: &args{
				major: 5,
				minor: 8,
				patch: 3,
			},
			want:    329731,
			wantErr: false,
		},
		{
			name: "invalid major value",
			args: &args{
				major: "ad",
				minor: 1,
				patch: 3,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "invalid minor value",
			args: &args{
				major: 0,
				minor: "dsf",
				patch: 9,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "invalid patch value",
			args: &args{
				major: 0,
				minor: 3,
				patch: "ds",
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "empty values",
			args: &args{
				major: "",
				minor: "",
				patch: "",
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.setup()

			got, err := CurrentKernelVersion()
			if (err != nil) != tt.wantErr {
				t.Errorf("CurrentKernelVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CurrentKernelVersion() = %v, want %v", got, tt.want)
			}

			tt.args.teardown()
		})
	}
}

// TestPrintEvent is a Go function for testing the PrintEvent function.
func TestPrintEvent(t *testing.T) {
	type args struct {
		data map[string]any
		t    int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "empty map",
			args: args{
				data: map[string]any{},
				t:    0,
			},
		}, {
			name: "non empty map",
			args: args{
				data: map[string]any{
					"eventId":   "sys_test",
					"syscallId": -1,
				},
				t: 0,
			},
		}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			PrintEvent(tt.args.data, tt.args.t)
		})
	}
}
