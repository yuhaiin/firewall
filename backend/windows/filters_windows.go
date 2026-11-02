//go:build windows && (amd64 || arm64)

package windows

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"runtime"
	"unsafe"

	fw "github.com/yuhaiin/firewall"
	"golang.org/x/sys/windows"
)

// GUIDs are the documented FWPM_LAYER_ALE_AUTH_* and FWPM_CONDITION_* keys.
var (
	connect4      = mustGUID("c38d57d1-05a7-4c33-904f-7fbceee60e82")
	connect6      = mustGUID("4a72393b-319f-44bc-84c3-ba54dcb3b6b4")
	receive4      = mustGUID("e1cd9fe7-f4b5-4273-96c0-592e487b8650")
	receive6      = mustGUID("a3b42c97-9f04-4672-b87e-cee9c483257f")
	localAddress  = mustGUID("d9ee00de-c1ef-4617-bfe3-ffd8f5a08957")
	remoteAddress = mustGUID("b235ae9a-1d64-49b8-a44c-5ff3d9095045")
	localPort     = mustGUID("0c1ba1af-5765-453f-af22-a8f791ac775b")
	remotePort    = mustGUID("c35a604d-d22b-4e1a-91b4-68f674ee674b")
	ipProtocol    = mustGUID("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7")
	appID         = mustGUID("d78e1e87-8644-4ea5-9437-d809ecefc971")
	userID        = mustGUID("af043a0a-b34d-4f86-979c-c90371af6e66")
)

func mustGUID(s string) windows.GUID {
	g, err := windows.GUIDFromString("{" + s + "}")
	if err != nil {
		panic(err)
	}
	return g
}

func (b *Backend) compile(s fw.Snapshot, a *arena) ([]*filter, error) {
	var out []*filter
	add := func(id string, d fw.Direction, family fw.Family, act fw.Action, weight uint64, terms []condition) {
		layer := connect4
		if family == fw.IPv6 {
			layer = connect6
		}
		if d == fw.Inbound {
			layer = receive4
			if family == fw.IPv6 {
				layer = receive6
			}
		}
		f := &filter{Key: guid(b.config.Owner, id), Display: display{Name: text(id)}, Provider: &b.provider, Layer: layer, Sublayer: b.sublayer, Weight: ptrValue(a, 4, new(weight)), Count: uint32(len(terms)), Action: action{Type: 0x1002}}
		if len(terms) > 0 {
			f.Conditions = &terms[0]
			a.roots = append(a.roots, terms)
		}
		if act == fw.Drop {
			f.Action.Type = 0x1001
		}
		if s.Policy.Lifetime == fw.Persistent {
			f.Flags = 1
		}
		out = append(out, f)
	}
	for i, r := range s.Rules {
		for j, term := range r.Terms {
			for _, family := range []fw.Family{fw.IPv4, fw.IPv6} {
				if r.Family != fw.Dual && r.Family != family {
					continue
				}
				conditions, possible, err := compileTerm(a, term, r.Direction, family)
				if err != nil {
					return nil, fmt.Errorf("rule %s: %w", r.ID, err)
				}
				if possible {
					add(fmt.Sprintf("%s/%s/%d", r.ID, family, j), r.Direction, family, r.Action, ^uint64(0)-uint64(i), conditions)
				}
			}
		}
	}
	for _, d := range []fw.Direction{fw.Inbound, fw.Outbound} {
		if act, ok := s.Policy.Defaults[d]; ok {
			for _, family := range []fw.Family{fw.IPv4, fw.IPv6} {
				add("default/"+string(d)+"/"+string(family), d, family, act, 1, nil)
			}
		}
	}
	return out, nil
}

func compileTerm(a *arena, term []fw.Literal, d fw.Direction, family fw.Family) ([]condition, bool, error) {
	var out []condition
	seen := map[windows.GUID]bool{}
	for _, l := range term {
		m := l.Match
		c := condition{}
		if l.Not {
			c.Op = 10
		}
		switch m.Field {
		case fw.Protocol:
			c.Field = ipProtocol
			c.Value = value{Type: 1, Data: uintptr(m.Number)}
		case fw.SourcePrefix, fw.DestinationPrefix:
			if m.Prefix.Addr().Is4() != (family == fw.IPv4) {
				if l.Not {
					continue
				}
				return nil, false, nil
			}
			c.Field = remoteAddress
			if (m.Field == fw.SourcePrefix) == (d == fw.Outbound) {
				c.Field = localAddress
			}
			if family == fw.IPv4 {
				address := m.Prefix.Addr().As4()
				mask := ^uint32(0) << uint(32-m.Prefix.Bits())
				c.Value = ptrValue(a, 0x100, &v4Mask{Address: binary.BigEndian.Uint32(address[:]), Mask: mask})
			} else {
				c.Value = ptrValue(a, 0x101, &v6Mask{Address: m.Prefix.Addr().As16(), Bits: uint8(m.Prefix.Bits())})
			}
		case fw.SourcePort, fw.DestinationPort:
			c.Field = remotePort
			if (m.Field == fw.SourcePort) == (d == fw.Outbound) {
				c.Field = localPort
			}
			if m.Ports.First == m.Ports.Last {
				c.Value = value{Type: 2, Data: uintptr(m.Ports.First)}
			} else {
				if l.Not {
					return nil, false, fmt.Errorf("%w: negated WFP port range; use OR of explicit complementary ranges", fw.ErrUnsupported)
				}
				c.Op = 5
				c.Value = ptrValue(a, 0x102, &valueRange{Low: value{Type: 2, Data: uintptr(m.Ports.First)}, High: value{Type: 2, Data: uintptr(m.Ports.Last)}})
			}
		case fw.Application:
			if !filepath.IsAbs(m.Text) {
				return nil, false, fmt.Errorf("%w: WFP application requires an absolute executable path", fw.ErrInvalid)
			}
			path := text(m.Text)
			var id *blob
			if err := call(getAppID, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&id))); err != nil {
				return nil, false, wrap(err)
			}
			runtime.KeepAlive(path)
			a.native = append(a.native, id)
			c.Field = appID
			c.Value = value{Type: 12, Data: uintptr(unsafe.Pointer(id))}
		case fw.User:
			if l.Not {
				return nil, false, fmt.Errorf("%w: negated user descriptor", fw.ErrUnsupported)
			}
			if _, err := windows.StringToSid(m.Text); err != nil {
				return nil, false, fmt.Errorf("%w: user requires a Windows SID: %v", fw.ErrInvalid, err)
			}
			// ALE_USER_ID performs an access check against a self-relative SD.
			sd, err := windows.SecurityDescriptorFromString("D:(A;;0x1;;;" + m.Text + ")")
			if err != nil {
				return nil, false, err
			}
			a.roots = append(a.roots, sd)
			data := unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length())
			bb := bytesBlob(data)
			c.Field = userID
			c.Value = ptrValue(a, 14, &bb)
		default:
			return nil, false, fmt.Errorf("%w: WFP field %s", fw.ErrUnsupported, m.Field)
		}
		// Multiple WFP conditions with the same field can have OR semantics.
		// Reject rather than widen an AND term; callers can intersect beforehand.
		if seen[c.Field] {
			return nil, false, fmt.Errorf("%w: repeated WFP field in AND term", fw.ErrUnsupported)
		}
		seen[c.Field] = true
		out = append(out, c)
	}
	return out, true, nil
}
