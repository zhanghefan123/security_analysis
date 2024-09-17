/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/
package birdsnest

import (
	"fmt"
)

type SprintfError string

// Error error information
func (s SprintfError) Error() string {
	return string(s)
}

func NewError(s string, args ...interface{}) SprintfError {
	return SprintfError(fmt.Sprintf(s, args...))
}
