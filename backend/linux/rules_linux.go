package linux

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/google/nftables/expr"
	fw "github.com/yuhaiin/firewall"
	"golang.org/x/sys/unix"
)

func expressions(term []fw.Literal, family fw.Family, d fw.Direction) ([]expr.Any, bool, error) {
	nf := byte(unix.NFPROTO_IPV4)
	if family == fw.IPv6 {
		nf = unix.NFPROTO_IPV6
	}
	es := []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nf}}}
	// Protocol dependency must precede transport payload loads regardless of
	// the application's expression order. IPv6 extension headers use L4PROTO.
	ordered := make([]fw.Literal, 0, len(term))
	for _, l := range term {
		if l.Match.Field == fw.Protocol {
			ordered = append(ordered, l)
		}
	}
	for _, l := range term {
		if l.Match.Field != fw.Protocol {
			ordered = append(ordered, l)
		}
	}
	for _, l := range ordered {
		m := l.Match
		op := expr.CmpOpEq
		if l.Not {
			op = expr.CmpOpNeq
		}
		switch m.Field {
		case fw.Protocol:
			es = append(es, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: op, Register: 1, Data: []byte{byte(m.Number)}})
		case fw.SourcePrefix, fw.DestinationPrefix:
			if m.Prefix.Addr().Is4() != (family == fw.IPv4) {
				if l.Not {
					continue
				}
				return nil, false, nil
			}
			offset, length := uint32(12), uint32(4)
			if family == fw.IPv6 {
				offset, length = 8, 16
			}
			if m.Field == fw.DestinationPrefix {
				offset += length
			}
			mask := []byte(net.CIDRMask(m.Prefix.Bits(), int(length*8)))
			addr := m.Prefix.Addr().AsSlice()
			es = append(es, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: mask, Xor: make([]byte, length)}, &expr.Cmp{Op: op, Register: 1, Data: addr})
		case fw.SourcePort, fw.DestinationPort:
			offset := uint32(0)
			if m.Field == fw.DestinationPort {
				offset = 2
			}
			es = append(es, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2})
			if m.Ports.First == m.Ports.Last {
				es = append(es, &expr.Cmp{Op: op, Register: 1, Data: be16(m.Ports.First)})
			} else {
				es = append(es, &expr.Range{Op: op, Register: 1, FromData: be16(m.Ports.First), ToData: be16(m.Ports.Last)})
			}
		case fw.InputInterface, fw.OutputInterface:
			if len(m.Text) > 15 {
				return nil, false, fmt.Errorf("%w: interface name exceeds IFNAMSIZ", fw.ErrInvalid)
			}
			key := expr.MetaKeyIIFNAME
			if m.Field == fw.OutputInterface {
				key = expr.MetaKeyOIFNAME
			}
			name := make([]byte, 16)
			copy(name, m.Text)
			es = append(es, &expr.Meta{Key: key, Register: 1}, &expr.Cmp{Op: op, Register: 1, Data: name})
		case fw.User:
			// skuid is a local output socket property; no universal PID claim.
			if d != fw.Outbound {
				return nil, false, fmt.Errorf("%w: UID only at output", fw.ErrUnsupported)
			}
			uid, err := strconv.ParseUint(m.Text, 10, 32)
			if err != nil {
				return nil, false, fmt.Errorf("%w: numeric UID required", fw.ErrInvalid)
			}
			es = append(es, &expr.Meta{Key: expr.MetaKeySKUID, Register: 1}, &expr.Cmp{Op: op, Register: 1, Data: native32(uint32(uid))})
		case fw.ConnectionState:
			es = append(es, &expr.Ct{Key: expr.CtKeySTATE, Register: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: native32(m.Number), Xor: make([]byte, 4)})
			ctOp := expr.CmpOpNeq
			if l.Not {
				ctOp = expr.CmpOpEq
			}
			es = append(es, &expr.Cmp{Op: ctOp, Register: 1, Data: make([]byte, 4)})
		case fw.PacketMark:
			es = append(es, &expr.Meta{Key: expr.MetaKeyMARK, Register: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: native32(m.Mask), Xor: make([]byte, 4)}, &expr.Cmp{Op: op, Register: 1, Data: native32(m.Number)})
		default:
			return nil, false, fmt.Errorf("%w: %s", fw.ErrUnsupported, m.Field)
		}
	}
	return es, true, nil
}
func be16(n uint16) []byte     { return binary.BigEndian.AppendUint16(nil, n) }
func native32(n uint32) []byte { return binary.NativeEndian.AppendUint32(nil, n) }
func verdict(a fw.Action) []expr.Any {
	switch a {
	case fw.Allow:
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
	case fw.Drop:
		return []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	case fw.Reject:
		return []expr.Any{&expr.Reject{Type: 2, Code: 1}}
	case fw.Log:
		return []expr.Any{&expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte("firewall ")}}
	}
	panic("validated action required")
}
