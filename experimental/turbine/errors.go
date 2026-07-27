package turbine

import (
	R "github.com/sagernet/sing-box/route/rule"
	tun "github.com/sagernet/sing-tun"
)

// rejected returns a silent drop error recognized by the router (R.IsRejected).
func rejected() error {
	return &R.RejectedError{Cause: tun.ErrDrop}
}

// IsRejected reports whether err is a silent policy rejection.
func IsRejected(err error) bool {
	return R.IsRejected(err)
}
