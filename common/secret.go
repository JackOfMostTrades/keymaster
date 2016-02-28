package common

import (
	"time"
)

type Secret struct {
	CertId     int64
	Secret     []byte
	ValidFrom  time.Time
	ValidUntil time.Time
}
