package linux

import (
	"fmt"
	"syscall"

	fw "github.com/yuhaiin/firewall"
	"golang.org/x/sys/unix"
)

// MarkReservation reserves bits for capture/routing coordination. OtherMasks
// must be supplied by the route/capture owner; arbitrary external mark users
// cannot be discovered reliably by this library. Marks never imply Allow.
type MarkReservation struct {
	Mask, Value uint32
	OtherMasks  []uint32
}

// Validate rejects overlapping reservations and values outside the mask.
func (r MarkReservation) Validate() error {
	if r.Mask == 0 || r.Value & ^r.Mask != 0 {
		return fmt.Errorf("%w: mark mask/value", fw.ErrInvalid)
	}
	for _, m := range r.OtherMasks {
		if m&r.Mask != 0 {
			return fmt.Errorf("%w: reserved mark bits overlap", fw.ErrOwnership)
		}
	}
	return nil
}

// SetSocketMark preserves every unreserved SO_MARK bit. Call before connecting
// or sending on a newly created socket. The caller owns routing and capture.
func SetSocketMark(raw syscall.RawConn, r MarkReservation) error {
	if err := r.Validate(); err != nil {
		return err
	}
	var inner error
	err := raw.Control(func(fd uintptr) {
		old, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
		if e != nil {
			inner = e
			return
		}
		inner = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int((uint32(old) & ^r.Mask)|r.Value))
	})
	if err != nil {
		return err
	}
	return inner
}
