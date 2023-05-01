package sh_ip_route

import (
	"github.com/ivankuchin/excessive-acl/internal/utils"
)

type routingEntry struct {
	prefix   utils.AddressObject
	iface    string
	next_hop uint32
	parent   *routingEntry
	children []*routingEntry
}

type RoutingTable struct {
	entry []routingEntry
}
