// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package utils

import (
	"testing"
)

// TestInt8 tests the Int8 function.
func TestInt8(t *testing.T) {
	type args struct {
		b   []byte
		pos int
	}
	tests := []struct {
		name    string
		args    args
		want    int8
		wantErr bool
	}{
		{
			name: "valid values",
			args: args{
				b:   []byte{1, 2, 3},
				pos: 0,
			},
			want:    1,
			wantErr: false,
		},
		{
			name: "valid values for negative result",
			args: args{
				b:   []byte{200, 2, 3},
				pos: 0,
			},
			want:    -56,
			wantErr: false,
		},
		{
			name: "invalid pos",
			args: args{
				b:   []byte{1, 2, 3},
				pos: 4,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "invalid negative pos",
			args: args{
				b:   []byte{1, 2, 3},
				pos: -1,
			},
			want:    0,
			wantErr: true,
		}, {
			name: "empty byte slice",
			args: args{
				b:   []byte{},
				pos: 1,
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Int8(tt.args.b, tt.args.pos)
			if (err != nil) != tt.wantErr {
				t.Errorf("Int8() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Int8() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestInt16 tests the Int16 function.
func TestInt16(t *testing.T) {
	type args struct {
		b   []byte
		pos int
	}
	tests := []struct {
		name    string
		args    args
		want    int16
		wantErr bool
	}{
		{
			name: "valid values",
			args: args{
				b:   []byte{1, 2, 3},
				pos: 0,
			},
			want:    513,
			wantErr: false,
		},
		{
			name: "invalid pos",
			args: args{
				b:   []byte{1, 2, 3},
				pos: 3,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "invalid negative pos",
			args: args{
				b:   []byte{1, 2, 3},
				pos: -1,
			},
			want:    0,
			wantErr: true,
		}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Int16(tt.args.b, tt.args.pos)
			if (err != nil) != tt.wantErr {
				t.Errorf("Int16() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Int16() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestInt32 tests the Int32 function.
func TestInt32(t *testing.T) {
	type args struct {
		b   []byte
		pos int
	}
	tests := []struct {
		name    string
		args    args
		want    int32
		wantErr bool
	}{
		{
			name: "valid values",
			args: args{
				b:   []byte{1, 2, 3, 4, 5},
				pos: 1,
			},
			want:    84148994,
			wantErr: false,
		},
		{
			name: "invalid pos",
			args: args{
				b:   []byte{1, 2, 3, 4},
				pos: 3,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "invalid negative pos",
			args: args{
				b:   []byte{1, 2, 3, 4},
				pos: -1,
			},
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Int32(tt.args.b, tt.args.pos)
			if (err != nil) != tt.wantErr {
				t.Errorf("Int32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Int32() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestInt64 tests the Int64 function.
func TestInt64(t *testing.T) {
	type args struct {
		b   []byte
		pos int
	}
	tests := []struct {
		name    string
		args    args
		want    int64
		wantErr bool
	}{
		{
			name: "valid values",
			args: args{
				b:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
				pos: 1,
			},
			want:    650777868590383874,
			wantErr: false,
		},
		{
			name: "invalid pos",
			args: args{
				b:   []byte{1, 2, 3, 4, 5, 6, 7, 8},
				pos: 3,
			},
			want:    0,
			wantErr: true,
		}, {
			name: "invalid negative pos",
			args: args{
				b:   []byte{1, 2, 3, 4},
				pos: -1,
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Int64(tt.args.b, tt.args.pos)
			if (err != nil) != tt.wantErr {
				t.Errorf("Int64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Int64() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestUint8 tests the Uint8 function.
func TestUint8(t *testing.T) {
	type args struct {
		b   []byte
		pos int
	}
	tests := []struct {
		name    string
		args    args
		want    uint8
		wantErr bool
	}{
		{
			name: "valid values",
			args: args{
				b:   []byte{1, 2, 3},
				pos: 0,
			},
			want:    1,
			wantErr: false,
		},
		{
			name: "valid values with max value",
			args: args{
				b:   []byte{255, 2, 3},
				pos: 0,
			},
			want:    255,
			wantErr: false,
		},
		{
			name: "invalid pos",
			args: args{
				b:   []byte{1, 2, 3},
				pos: 4,
			},
			want:    0,
			wantErr: true,
		}, {
			name: "invalid negative pos",
			args: args{
				b:   []byte{1, 2, 3},
				pos: -1,
			},
			want:    0,
			wantErr: true,
		}, {
			name: "empty slice",
			args: args{
				b:   []byte{},
				pos: 0,
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Uint8(tt.args.b, tt.args.pos)
			if (err != nil) != tt.wantErr {
				t.Errorf("Uint8() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Uint8() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestUint16 tests the Uint16 function.
func TestUint16(t *testing.T) {
	type args struct {
		b   []byte
		pos int
	}
	tests := []struct {
		name    string
		args    args
		want    uint16
		wantErr bool
	}{
		{
			name: "valid values",
			args: args{
				b:   []byte{34, 22, 3},
				pos: 0,
			},
			want:    5666,
			wantErr: false,
		},
		{
			name: "invalid pos",
			args: args{
				b:   []byte{1, 2, 3},
				pos: 3,
			},
			want:    0,
			wantErr: true,
		}, {
			name: "invalid negative pos",
			args: args{
				b:   []byte{1, 2, 3},
				pos: -1,
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Uint16(tt.args.b, tt.args.pos)
			if (err != nil) != tt.wantErr {
				t.Errorf("Uint16() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Uint16() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestUint32 tests the Uint32 function.
func TestUint32(t *testing.T) {
	type args struct {
		b   []byte
		pos int
	}
	tests := []struct {
		name    string
		args    args
		want    uint32
		wantErr bool
	}{
		{
			name: "valid values",
			args: args{
				b:   []byte{255, 255, 3, 4, 5},
				pos: 1,
			},
			want:    84149247,
			wantErr: false,
		},
		{
			name: "invalid pos",
			args: args{
				b:   []byte{1, 2, 3, 4},
				pos: 3,
			},
			want:    0,
			wantErr: true,
		}, {
			name: "invalid negative pos",
			args: args{
				b:   []byte{1, 2, 3, 4},
				pos: -1,
			},
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Uint32(tt.args.b, tt.args.pos)
			if (err != nil) != tt.wantErr {
				t.Errorf("Uint32() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Uint32() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestUint64 tests the Uint64 function.
func TestUint64(t *testing.T) {
	type args struct {
		b   []byte
		pos int
	}
	tests := []struct {
		name    string
		args    args
		want    uint64
		wantErr bool
	}{
		{
			name: "valid values",
			args: args{
				b:   []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 26, 78, 93, 98},
				pos: 4,
			},
			want:    1945555039024054271,
			wantErr: false,
		},
		{
			name: "invalid pos",
			args: args{
				b:   []byte{1, 2, 3, 4},
				pos: 10,
			},
			want:    0,
			wantErr: true,
		}, {
			name: "invalid negative pos",
			args: args{
				b:   []byte{1, 2, 3, 4},
				pos: -1,
			},
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Uint64(tt.args.b, tt.args.pos)
			if (err != nil) != tt.wantErr {
				t.Errorf("Uint64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Uint64() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestToString tests the ToString function.
func TestToString(t *testing.T) {
	type args struct {
		b    []byte
		pos  int
		size int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "valid values",
			args: args{
				b:    []byte{1, 2, 3, 4, 5, 47, 98, 105, 110, 0, 34, 93, 39},
				pos:  5,
				size: 5,
			},
			want: "/bin",
		}, {
			name: "invalid position",
			args: args{
				b:    []byte{1, 2, 3, 4, 5, 47, 98, 105, 110, 0, 34, 93, 39},
				pos:  5,
				size: 10,
			},
			want: "",
		}, {
			name: "invalid negative position",
			args: args{
				b:    []byte{1, 2, 3, 4, 5, 47, 98, 105, 110, 0, 34, 93, 39},
				pos:  -1,
				size: 5,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToString(tt.args.b, tt.args.pos, tt.args.size); got != tt.want {
				t.Errorf("ToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIpv4 tests the Ipv4 function.
func TestIpv4(t *testing.T) {
	type args struct {
		b   []byte
		pos int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "valid values",
			args: args{
				b:   []byte{1, 2, 3, 4},
				pos: 0,
			},
			want: "1.2.3.4",
		}, {
			name: "invalid position",
			args: args{
				b:   []byte{1, 2, 3, 4},
				pos: 2,
			},
			want: "",
		}, {
			name: "invalid negative position",
			args: args{
				b:   []byte{1, 2, 3, 4},
				pos: -1,
			},
			want: "",
		}, {
			name: "valid values case 2",
			args: args{
				b:   []byte{1, 2, 192, 168, 0, 1},
				pos: 2,
			},
			want: "192.168.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Ipv4(tt.args.b, tt.args.pos); got != tt.want {
				t.Errorf("Ipv4() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIpv6 tests the Ipv6 function.
func TestIpv6(t *testing.T) {
	type args struct {
		b   []byte
		pos int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "valid values",
			args: args{
				b:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				pos: 0,
			},
			want: "102:304:506:708:90a:b0c:d0e:f10",
		}, {
			name: "invalid position",
			args: args{
				b:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				pos: 2,
			},
			want: "",
		}, {
			name: "invalid negative position",
			args: args{
				b:   []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
				pos: -1,
			},
			want: "",
		}, {
			name: "all zeros",
			args: args{
				b:   []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				pos: 3,
			},
			want: "::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Ipv6(tt.args.b, tt.args.pos); got != tt.want {
				t.Errorf("Ipv6() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNtohs tests the Ntohs function.
func TestNtohs(t *testing.T) {
	type args struct {
		n uint16
	}
	tests := []struct {
		name string
		args args
		want uint16
	}{
		{
			name: "valid values",
			args: args{
				n: 0x1234,
			},
			want: 0x3412,
		}, {
			name: "valid values case 2",
			args: args{
				n: 36895,
			},
			want: 8080,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Ntohs(tt.args.n); got != tt.want {
				t.Errorf("Ntohs() = %v, want %v", got, tt.want)
			}
		})
	}
}
