// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"fmt"
	"reflect"
	"testing"
)

// TestLoadTarianEvents tests the LoadTarianEvents function. It ensures that it correctly loads all events.
func TestLoadTarianEvents(t *testing.T) {
	tests := []struct {
		name string
	}{{name: "valid case"}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			LoadTarianEvents()

			if len(Events) != 32 {
				t.Errorf("LoadTarianEvents() = %v, want %v", len(Events), 32)
			}
		})
	}
}

// TestParam_processValue tests the processValue function.
func TestParam_processValue(t *testing.T) {
	type fields struct {
		name      string
		paramType TarianParamType
		linuxType string
		function  func(any) (string, error)
	}
	type args struct {
		val interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    Arg
		wantErr bool
	}{
		{
			name: "function error",
			fields: fields{
				name:      "test",
				paramType: TDT_S32,
				linuxType: "int",
				function: func(v interface{}) (string, error) {
					return "", fmt.Errorf("test")
				},
			},
			args: args{
				val: 123,
			},
			want:    Arg{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Param{
				name:      tt.fields.name,
				paramType: tt.fields.paramType,
				linuxType: tt.fields.linuxType,
				function:  tt.fields.function,
			}
			got, err := p.processValue(tt.args.val)
			if (err != nil) != tt.wantErr {
				t.Errorf("Param.processValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Param.processValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
