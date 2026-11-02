package linux

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	fw "github.com/yuhaiin/firewall"
	"golang.org/x/sys/unix"
)

// Single-address OR lists share one native lookup and counter per family.
// More complex terms retain exact ordered predicate semantics.
func addressSetEligible(r fw.CompiledRule) bool {
	if len(r.Terms) < 4 {
		return false
	}
	var field fw.Field
	for _, term := range r.Terms {
		if len(term) != 1 || term[0].Not {
			return false
		}
		m := term[0].Match
		if m.Field != fw.SourcePrefix && m.Field != fw.DestinationPrefix {
			return false
		}
		if m.Prefix.Bits() != m.Prefix.Addr().BitLen() {
			return false
		}
		if field != "" && field != m.Field {
			return false
		}
		field = m.Field
	}
	return true
}
func addressSet(c *nftables.Conn, table *nftables.Table, r fw.CompiledRule, family fw.Family, id uint32) ([]expr.Any, error) {
	seen := map[netip.Addr]bool{}
	var elements []nftables.SetElement
	for _, term := range r.Terms {
		addr := term[0].Match.Prefix.Addr()
		if addr.Is4() != (family == fw.IPv4) || seen[addr] {
			continue
		}
		seen[addr] = true
		elements = append(elements, nftables.SetElement{Key: addr.AsSlice()})
	}
	if len(elements) == 0 {
		return nil, nil
	}
	nf, offset, length := byte(unix.NFPROTO_IPV4), uint32(12), uint32(4)
	kind := nftables.TypeIPAddr
	if family == fw.IPv6 {
		nf, offset, length = unix.NFPROTO_IPV6, 8, 16
		kind = nftables.TypeIP6Addr
	}
	if r.Terms[0][0].Match.Field == fw.DestinationPrefix {
		offset += length
	}
	set := &nftables.Set{Table: table, ID: id, Name: fmt.Sprintf("addresses_%d", id), Constant: true, KeyType: kind}
	if err := c.AddSet(set, elements); err != nil {
		return nil, err
	}
	return []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{nf}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length}, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID}}, nil
}
