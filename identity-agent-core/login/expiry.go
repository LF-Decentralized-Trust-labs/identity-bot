package login

import (
	"errors"
	"time"
)

// ErrExpired is a request whose expiry has passed. A relayed code must not
// stay valid forever, so nothing is signed or disclosed for one.
var ErrExpired = errors.New("this request has expired")

// ErrExpiryUnreadable is a request whose expiry is missing or not RFC 3339. A
// request whose lifetime cannot be read is not proven to be alive.
var ErrExpiryUnreadable = errors.New("this request's expiry could not be read")

// ExpirySkew is how far past its expiry a request is still accepted, so a
// small clock difference between the site and this device cannot break a
// request that is really still live.
const ExpirySkew = 30 * time.Second

// CheckExpiry refuses an expiry that is missing, unreadable, or further in
// the past than ExpirySkew.
func CheckExpiry(expiry string, now time.Time) error {
	if expiry == "" {
		return ErrExpiryUnreadable
	}
	at, err := parseRFC3339(expiry)
	if err != nil {
		return ErrExpiryUnreadable
	}
	if at.Before(now.Add(-ExpirySkew)) {
		return ErrExpired
	}
	return nil
}
