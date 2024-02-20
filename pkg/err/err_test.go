// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package err

import "testing"

// TestNew tests the New function. It checks if the New function returns an error with the correct caller and an empty message.
func TestNew(t *testing.T) {
	// testCases contains the test cases for the TestNew function.
	testCases := []struct {
		name   string
		caller string
	}{
		{
			name:   "Empty Caller",
			caller: "",
		}, {
			name:   "Non Empty Caller",
			caller: "test",
		},
	}

	// Iterate over the test cases.
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Call the New function and check the returned error.
			err := New(test.caller)

			// Check if the caller of the error is correct.
			if err.caller != test.caller {
				t.Errorf("Expected caller to be %s, got %s", test.caller, err.caller)
			}

			// Check if the message of the error is empty.
			if err.message != "" {
				t.Errorf("Expected message to be empty, got %q", err.message)
			}
		})
	}
}

// TestThrowf tests the Throwf method. It checks if the Throwf method returns an error with the correct message.
func TestThrowf(t *testing.T) {
	// testCases contains the test cases for the TestThrowf function.
	testCases := []struct {
		name            string
		format          string
		args            []any
		expectedMessage string
	}{
		{
			name:            "No Argument",
			format:          "This is an simple error message.",
			args:            []any{},
			expectedMessage: "This is an simple error message.",
		}, {
			name:            "Single Argument",
			format:          "This is a formatted error message: %d",
			args:            []any{42},
			expectedMessage: "This is a formatted error message: 42",
		}, {
			name:            "Multiple Arguments",
			format:          "Formatted message with %s and %d",
			args:            []any{"string", 42},
			expectedMessage: "Formatted message with string and 42",
		}, {
			name:            "Invalid Arguments",
			format:          "This is an error proned format string %d %s",
			args:            []any{10, true},
			expectedMessage: "This is an error proned format string 10 %!s(bool=true)",
		}, {
			name:            "Missing Arguments",
			format:          "This is an error proned format string %d %s",
			args:            []any{},
			expectedMessage: "This is an error proned format string %!d(MISSING) %!s(MISSING)",
		},
	}

	// Iterate over the test cases.
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Create a new error and call the Throwf method.
			caller := "TestThrowf"
			err := New(caller).Throwf(test.format, test.args...)

			// Check if the message of the error is correct.
			if err.message != test.expectedMessage {
				t.Errorf("Expected message to be %s, got %s", test.expectedMessage, err.message)
			}
		})
	}
}

// TestThrow tests the Throw method. It checks if the Throw method returns an error with the correct message.
func TestThrow(t *testing.T) {
	// tests contains the test cases for the TestThrow function.
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "Simple Message",
			message:         "This is an error message",
			expectedMessage: "This is an error message",
		},
	}

	// Iterate over the test cases.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new error and call the Throw method.
			caller := "TestThrow"
			err := New(caller).Throw(tt.message)

			// Check if the message of the error is correct.
			if err.message != tt.expectedMessage {
				t.Errorf("Expected message to be %s, got %s", tt.expectedMessage, err.message)
			}
		})
	}
}

// TestError tests the Error method. It checks if the Error method returns the correct error message.
func TestError(t *testing.T) {
	// testCases contains the test cases for the TestError function.
	testCases := []struct {
		name          string
		caller        string
		callFunc      func(e *Err) *Err
		expectedError string
	}{
		{
			name:   "Throw",
			caller: "TestThrow",
			callFunc: func(e *Err) *Err {
				return e.Throw("Error message")
			},
			expectedError: "TestThrowError: Error message",
		}, {
			name:   "Throwf",
			caller: "TestThrowf",
			callFunc: func(e *Err) *Err {
				return e.Throwf("Error number %d", 80)
			},
			expectedError: "TestThrowfError: Error number 80",
		},
	}

	// Iterate over the test cases.
	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Create a new error and call the test function
			err := New(test.caller)
			e := test.callFunc(err)

			// Call the Error method and check the returned error message.
			if errorMessage := e.Error(); errorMessage != test.expectedError {
				t.Errorf("Expected error message to be %s, got %s", test.expectedError, errorMessage)
			}
		})
	}
}
