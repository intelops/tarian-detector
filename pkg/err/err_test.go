// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package err

import (
	"reflect"
	"testing"
)

// TestNew tests the New function. It checks if the New function returns an error with the correct caller and an empty message.
func TestNew(t *testing.T) {
	type args struct {
		caller string
	}
	tests := []struct {
		name string
		args args
		want *Err
	}{
		{
			name: "valid values",
			args: args{
				caller: "TestNew",
			},
			want: &Err{
				caller: "TestNew",
			},
		}, {
			name: "empty caller",
			args: args{
				caller: "",
			},
			want: &Err{
				caller: "",
			},
		}, {
			name: "check for empty message",
			args: args{
				caller: "TestNew",
			},
			want: &Err{
				caller:  "TestNew",
				message: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.caller); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestErr_Throw tests the Throw method. It checks if the Throw method returns an error with the correct message.
func TestErr_Throwf(t *testing.T) {
	type fields struct {
		caller  string
		message string
	}
	type args struct {
		format string
		a      []any
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Err
	}{
		{
			name: "valid values",
			fields: fields{
				caller:  "TestErr_Throwf",
				message: "This is an error message",
			},
			args: args{
				format: "This is a formatted error message: %d",
				a:      []any{42},
			},
			want: &Err{
				caller:  "TestErr_Throwf",
				message: "This is a formatted error message: 42",
			},
		}, {
			name: "empty values",
			fields: fields{
				caller:  "TestErr_Throwf",
				message: "This is an error message",
			},
			args: args{
				format: "This is a formatted error message: %d",
				a:      []any{},
			},
			want: &Err{
				caller:  "TestErr_Throwf",
				message: "This is a formatted error message: %!d(MISSING)",
			},
		}, {
			name: "single argument",
			fields: fields{
				caller:  "TestErr_Throwf",
				message: "This is an error message",
			},
			args: args{
				format: "This is a formatted error message: %d",
				a:      []any{42},
			},
			want: &Err{
				caller:  "TestErr_Throwf",
				message: "This is a formatted error message: 42",
			},
		}, {
			name: "multiple arguments",
			fields: fields{
				caller: "TestErr_Throwf",
			},
			args: args{
				format: "This is a formatted error message: %d %s",
				a:      []any{42, "error"},
			},
			want: &Err{
				caller:  "TestErr_Throwf",
				message: "This is a formatted error message: 42 error",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Err{
				caller:  tt.fields.caller,
				message: tt.fields.message,
			}
			if got := e.Throwf(tt.args.format, tt.args.a...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Err.Throwf() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestErr_Throw tests the Throw method. It checks if the Throw method returns an error with the correct message.
func TestErr_Throw(t *testing.T) {
	type fields struct {
		caller  string
		message string
	}
	type args struct {
		message string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Err
	}{
		{
			name: "valid values",
			fields: fields{
				caller:  "TestErr_Throw",
				message: "This is an error message",
			},
			args: args{
				message: "This is an error message",
			},
			want: &Err{
				caller:  "TestErr_Throw",
				message: "This is an error message",
			},
		}, {
			name: "empty values",
			fields: fields{
				caller:  "TestErr_Throw",
				message: "This is an error message",
			},
			args: args{
				message: "",
			},
			want: &Err{
				caller:  "TestErr_Throw",
				message: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Err{
				caller:  tt.fields.caller,
				message: tt.fields.message,
			}
			if got := e.Throw(tt.args.message); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Err.Throw() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestErr_Error tests the Error method. It checks if the Error method returns the correct error message.
func TestErr_Error(t *testing.T) {
	type fields struct {
		caller  string
		message string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "valid values",
			fields: fields{
				caller:  "TestErr_Error",
				message: "This is an error message",
			},
			want: "TestErr_ErrorError: This is an error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Err{
				caller:  tt.fields.caller,
				message: tt.fields.message,
			}

			if got := e.Error(); got != tt.want {
				t.Errorf("Err.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}
