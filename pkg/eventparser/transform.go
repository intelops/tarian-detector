// SPDX-License-Identifier: Apache-2.0
// Copyright 2024 Authors of Tarian & the Organization created Tarian

package eventparser

import (
	"fmt"
	"strings"
)

const (
	AT_FDCWD              = -100
	AT_SYMLINK_FOLLOW     = 0x400
	AT_SYMLINK_NOFOLLOW   = 0x100
	AT_REMOVEDIR          = 0x200
	AT_NO_AUTOMOUNT       = 0x800
	AT_EMPTY_PATH         = 0x1000
	AT_STATX_SYNC_TYPE    = 0x6000
	AT_STATX_SYNC_AS_STAT = 0x0000
	AT_STATX_FORCE_SYNC   = 0x2000
	AT_STATX_DONT_SYNC    = 0x4000
	AT_RECURSIVE          = 0x8000
	AT_EACCESS            = 0x200
)

func parseExecveatDird(dird any) (string, error) {
	d, ok := dird.(int32)
	if !ok {
		return fmt.Sprintf("%v", dird), fmt.Errorf("parseExecveatDird: parse value error")
	}

	if d == AT_FDCWD {
		return "AT_FDCWD", nil
	}

	if d == AT_EMPTY_PATH {
		return "AT_EMPTY_PATH", nil
	}

	return fmt.Sprintf("%v", d), nil
}

func parseExecveatFlags(flag any) (string, error) {
	f, ok := flag.(int32)
	if !ok {
		return fmt.Sprintf("%v", flag), fmt.Errorf("parseExecveatFlags: parse value error")
	}

	var fs []string
	if f&AT_EMPTY_PATH == AT_EMPTY_PATH {
		fs = append(fs, "AT_EMPTY_PATH")
	}

	if f&AT_SYMLINK_NOFOLLOW == AT_SYMLINK_NOFOLLOW {
		fs = append(fs, "AT_SYMLINK_NOFOLLOW")
	}

	if len(fs) == 0 {
		return fmt.Sprintf("%v", flag), nil
	}

	return strings.Join(fs, "|"), nil
}
