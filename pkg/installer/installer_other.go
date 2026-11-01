//go:build !unix

package installer

import (
	"context"
	"errors"
)

var errUnsupported = errors.New("only supported on Linux")

func runAs(context.Context, string, string, string, string, ...string) (string, error) {
	return "", errUnsupported
}

func chownTo(string, string) error { return errUnsupported }
