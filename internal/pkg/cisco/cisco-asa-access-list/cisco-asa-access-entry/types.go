package ciscoasaaccessentry

import (
	"sync"

	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
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

type icmp_type_code struct {
	icmp_type int
	icmp_code int
}

type accessEntryCompiled struct {
	action action
	proto  *network_entities.Protocol

	// --- ip part
	src_addr_range utils.AddressObject
	dst_addr_range utils.AddressObject

	// --- tcp/udp part
	src_port_range port_range
	dst_port_range port_range

	// --- icmp part
	icmp icmp_type_code

	// --- flows mutex
	m *sync.Mutex
	// --- flows matched that acl entry
	flows []network_entities.Flow
	// --- count number of icmp flows
	icmp_flows icmp_type_code
}

type serviceObject struct {
	proto          []*network_entities.Protocol
	src_port_range []port_range
	dst_port_range []port_range
	icmp           []icmp_type_code
}

type AccessEntry struct {
	line     string
	compiled []accessEntryCompiled
}
