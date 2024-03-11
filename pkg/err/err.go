// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package err

import "fmt"

// Err is an exported type that encapsulates an error with a caller and a message.
type Err struct {
	caller  string
	message string
}

// New create new instance of Err with specified caller and an empty message.
// It returns the pointer to the created Err.
func New(caller string) *Err {
	return &Err{
		caller:  caller,
		message: "",
	}
}

// Throwf formats an error message according to a format specifier and returns the error.
// It updates the message of the Err with the formatted message.
func (e *Err) Throwf(format string, a ...any) *Err {
	e.message = fmt.Sprintf(format, a...)

	return e
}

// Throw updates the error message with the passed message and returns the error.
func (e *Err) Throw(message string) *Err {
	e.message = fmt.Sprint(message)

	return e
}

// Error returns a string that represents the Err.
// It combines the caller and the message of the Err.
func (e *Err) Error() string {
	return fmt.Sprintf("%sError: %s", e.caller, e.message)
}
