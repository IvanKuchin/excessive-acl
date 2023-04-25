package ciscoasaaccessentry

import (
	"net/netip"

	"github.com/ivankuchin/excessive-acl/internal/network_entities"
)

type action int

const (
	deny action = iota
	permit
)

type port uint16
type port_range struct {
	start  port
	finish port
}

type addr_range struct {
	start  netip.Addr
	finish netip.Addr
}

type icmp_type_code struct {
	icmp_type int
	icmp_code int
}

type accessEntryCompiled struct {
	action action
	proto  *network_entities.Protocol

	// --- ip part
	src_addr_range addressObject
	dst_addr_range addressObject

	// --- tcp/udp part
	src_port_range port_range
	dst_port_range port_range

	// --- icmp part
	icmp icmp_type_code
}

type serviceObject struct {
	proto          []*network_entities.Protocol
	src_port_range []port_range
	dst_port_range []port_range
	icmp           []icmp_type_code
}

type addressObject struct {
	start  uint32
	finish uint32
}

type AccessEntry struct {
	line     string
	compiled []accessEntryCompiled
}
