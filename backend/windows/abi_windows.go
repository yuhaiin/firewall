//go:build windows && (amd64 || arm64)

package windows

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These layouts mirror fwpmtypes.h/fwptypes.h for the 64-bit Windows ABI.
// Layout tests compare sizes and offsets with the SDK; 32-bit is unsupported.
type display struct{ Name, Description *uint16 }
type blob struct {
	Size uint32
	Data *byte
}
type value struct {
	Type uint32
	Data uintptr
}
type condition struct {
	Field windows.GUID
	Op    uint32
	Value value
}
type action struct {
	Type uint32
	Key  windows.GUID
}
type filter struct {
	Key             windows.GUID
	Display         display
	Flags           uint32
	Provider        *windows.GUID
	Data            blob
	Layer, Sublayer windows.GUID
	Weight          value
	Count           uint32
	Conditions      *condition
	Action          action
	_               uint32 // C aligns the context union to eight bytes.
	Context         [16]byte
	Reserved        *windows.GUID
	ID              uint64
	EffectiveWeight value
}
type provider struct {
	Key     windows.GUID
	Display display
	Flags   uint32
	Data    blob
	Service *uint16
}
type sublayer struct {
	Key      windows.GUID
	Display  display
	Flags    uint16
	Provider *windows.GUID
	Data     blob
	Weight   uint16
}
type session struct {
	Key                 windows.GUID
	Display             display
	Flags, Timeout, PID uint32
	SID                 *windows.SID
	Username            *uint16
	Kernel              int32
}
type enumTemplate struct {
	Provider    *windows.GUID
	Layer       windows.GUID
	Type, Flags uint32
	Context     unsafe.Pointer
	Count       uint32
	Conditions  *condition
	ActionMask  uint32
	Callout     *windows.GUID
}
type v4Mask struct{ Address, Mask uint32 }
type v6Mask struct {
	Address [16]byte
	Bits    uint8
}
type valueRange struct{ Low, High value }

var api = windows.NewLazySystemDLL("fwpuclnt.dll")
var (
	engineOpen        = api.NewProc("FwpmEngineOpen0")
	engineClose       = api.NewProc("FwpmEngineClose0")
	txnBegin          = api.NewProc("FwpmTransactionBegin0")
	txnCommit         = api.NewProc("FwpmTransactionCommit0")
	txnAbort          = api.NewProc("FwpmTransactionAbort0")
	providerAdd       = api.NewProc("FwpmProviderAdd0")
	providerGet       = api.NewProc("FwpmProviderGetByKey0")
	providerDelete    = api.NewProc("FwpmProviderDeleteByKey0")
	sublayerAdd       = api.NewProc("FwpmSubLayerAdd0")
	sublayerGet       = api.NewProc("FwpmSubLayerGetByKey0")
	sublayerDelete    = api.NewProc("FwpmSubLayerDeleteByKey0")
	filterAdd         = api.NewProc("FwpmFilterAdd0")
	filterDelete      = api.NewProc("FwpmFilterDeleteByKey0")
	filterEnumCreate  = api.NewProc("FwpmFilterCreateEnumHandle0")
	filterEnum        = api.NewProc("FwpmFilterEnum0")
	filterEnumDestroy = api.NewProc("FwpmFilterDestroyEnumHandle0")
	getAppID          = api.NewProc("FwpmGetAppIdFromFileName0")
	freeMemory        = api.NewProc("FwpmFreeMemory0")
)

func call(p *windows.LazyProc, args ...uintptr) error {
	r, _, _ := p.Call(args...)
	if r != 0 {
		return fmt.Errorf("%s: %w", p.Name, windows.Errno(r))
	}
	return nil
}
func release[T any](p **T) { freeMemory.Call(uintptr(unsafe.Pointer(p))) }
func bytesBlob(b []byte) blob {
	if len(b) == 0 {
		return blob{}
	}
	return blob{Size: uint32(len(b)), Data: &b[0]}
}
func text(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		panic("validated string contains NUL")
	}
	return p
}

// arena keeps Go storage referenced through native value unions alive for the
// duration of a synchronous API call. No Go pointer is retained by WFP.
type arena struct {
	roots  []any
	native []*blob
}

func ptrValue[T any](a *arena, kind uint32, p *T) value {
	a.roots = append(a.roots, p)
	return value{Type: kind, Data: uintptr(unsafe.Pointer(p))}
}
func (a *arena) close() {
	for _, p := range a.native {
		release(&p)
	}
	runtime.KeepAlive(a.roots)
}
