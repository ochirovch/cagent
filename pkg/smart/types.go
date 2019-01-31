package smart

import (
	"github.com/pkg/errors"
)

var (
	ErrNoDisksFound           = errors.New("smart: no physical disks found in the system")
	ErrUnderlyingToolNotFound = errors.New("smart: underlying tool not found")
)
