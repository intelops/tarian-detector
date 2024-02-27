// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"testing"
)

// Test_parseExecveatDird tests the parseExecveatDird function.
func Test_parseExecveatDird(t *testing.T) {
	type args struct {
		dird any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "valid values",
			args: args{
				dird: int32(-100),
			},
			want:    "AT_FDCWD",
			wantErr: false,
		},
		{
			name: "invalid value type",
			args: args{
				dird: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid undefined value ",
			args: args{
				dird: int32(256),
			},
			want:    "256",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExecveatDird(tt.args.dird)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseExecveatDird() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseExecveatDird() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_parseExecveatFlags tests the parseExecveatFlags function.
func Test_parseExecveatFlags(t *testing.T) {
	type args struct {
		flag any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid value type",
			args: args{
				flag: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid undefined values",
			args: args{
				flag: int32(0),
			},
			want:    "0",
			wantErr: false,
		},
		{
			name: "valid value",
			args: args{
				flag: int32(4096),
			},
			want:    "AT_EMPTY_PATH",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseExecveatFlags(tt.args.flag)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseExecveatFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseExecveatFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_parseCloneFlags tests the parseCloneFlags function.
func Test_parseCloneFlags(t *testing.T) {
	type args struct {
		flag any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid value type",
			args: args{
				flag: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid undefined values",
			args: args{
				flag: uint64(0),
			},
			want:    "0",
			wantErr: false,
		},
		{
			name: "valid value",
			args: args{
				flag: uint64(131072 | 14),
			},
			want:    "CLONE_NEWNS|SIGALRM",
			wantErr: false,
		},
		{
			name: "invalid value for signal",
			args: args{
				flag: uint64(131072 | 32),
			},
			want:    "CLONE_NEWNS|32",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCloneFlags(tt.args.flag)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseCloneFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseCloneFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_parseOpenMode tests the parseOpenMode function.
func Test_parseOpenMode(t *testing.T) {
	type args struct {
		mode any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid value type",
			args: args{
				mode: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid value",
			args: args{
				mode: uint32(384),
			},
			want:    "0600",
			wantErr: false,
		},
		{
			name: "valid value with sticky bit",
			args: args{
				mode: uint32(928),
			},
			want:    "1640",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOpenMode(tt.args.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOpenMode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseOpenMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_parseOpenFlags tests the parseOpenFlags function.
func Test_parseOpenFlags(t *testing.T) {
	type args struct {
		flags any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid value type",
			args: args{
				flags: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid value write only",
			args: args{
				flags: int32(1),
			},
			want:    "O_WRONLY",
			wantErr: false,
		},
		{
			name: "valid value read only",
			args: args{
				flags: int32(0 | 64),
			},
			want:    "O_RDONLY|O_CREAT",
			wantErr: false,
		},
		{
			name: "valid value read and write",
			args: args{
				flags: int32(2 | 64),
			},
			want:    "O_RDWR|O_CREAT",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOpenFlags(tt.args.flags)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOpenFlags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseOpenFlags() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_parseOpenat2Flags tests the parseOpenat2Flags function.
func Test_parseOpenat2Flags(t *testing.T) {
	type args struct {
		flags any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid value type",
			args: args{
				flags: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid value",
			args: args{
				flags: int64(0 | 64),
			},
			want:    "O_RDONLY|O_CREAT",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOpenat2Flags(tt.args.flags)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOpenat2Flags() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseOpenat2Flags() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_parseOpenat2Mode tests the parseOpenat2Mode function.
func Test_parseOpenat2Mode(t *testing.T) {
	type args struct {
		mode any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid value type",
			args: args{
				mode: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid value",
			args: args{
				mode: int64(384),
			},
			want:    "0600",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOpenat2Mode(tt.args.mode)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOpenat2Mode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseOpenat2Mode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_parseOpenat2Resolve tests the parseOpenat2Resolve function.
func Test_parseOpenat2Resolve(t *testing.T) {
	type args struct {
		resovle any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid value type",
			args: args{
				resovle: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid undefined value",
			args: args{
				resovle: int64(0),
			},
			want:    "0",
			wantErr: false,
		},
		{
			name: "valid value",
			args: args{
				resovle: int64(32),
			},
			want:    "RESOLVE_CACHED",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOpenat2Resolve(tt.args.resovle)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOpenat2Resolve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseOpenat2Resolve() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_parseSocketFamily tests the parseSocketFamily function.
func Test_parseSocketFamily(t *testing.T) {
	type args struct {
		n any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid value type",
			args: args{
				n: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid value",
			args: args{
				n: int32(45),
			},
			want:    "45",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSocketFamily(tt.args.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSocketFamily() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseSocketFamily() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_parseSocketType tests the parseSocketType function.
func Test_parseSocketType(t *testing.T) {
	type args struct {
		n any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid value type",
			args: args{
				n: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid undefine value",
			args: args{
				n: int32(11),
			},
			want:    "11",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSocketType(tt.args.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSocketType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseSocketType() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test_parseSocketProtocol tests the parseSocketProtocol function.
func Test_parseSocketProtocol(t *testing.T) {
	type args struct {
		n any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "invalid value type",
			args: args{
				n: 123,
			},
			want:    "123",
			wantErr: true,
		},
		{
			name: "valid value",
			args: args{
				n: int32(266),
			},
			want:    "266",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSocketProtocol(tt.args.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSocketProtocol() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseSocketProtocol() = %v, want %v", got, tt.want)
			}
		})
	}
}
