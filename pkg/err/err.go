// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Tarian & the Organization created Tarian

package err

import "fmt"

type Err struct {
	Caller  string
	Message string
}

func New(c string) *Err {
	return &Err{
		Caller:  c,
		Message: "",
	}
}

func (e *Err) Throwf(format string, a ...any) *Err {
	e.Message = fmt.Sprintf(format, a...)

	return e
}

func (e *Err) Throw(format string, a ...any) *Err {
	e.Message = fmt.Sprint(format)

	return e
}

func (e *Err) Error() string {
	return fmt.Sprintf("%sError: %s", e.Caller, e.Message)
}
