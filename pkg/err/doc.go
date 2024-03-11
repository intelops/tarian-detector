// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

// Package err provides functionalities for error handling in a structured manner.
// It defines a custom error type 'Err' that encapsulates an error with a caller and a message.
// This package is designed to provide more context about where an error was thrown.
//
// The Err struct contains two fields: 'caller' and 'message'.
// 'caller' represents the origin of the error, and 'message' provides details about the error.
//
// There are three main methods associated with the Err struct:
// - New: creates a new instance of Err with the specified caller and an empty message.
// - Throwf: formats an error message according to a format specifier.
// - Throw: updates the message of the Err with the passed message.
package err
