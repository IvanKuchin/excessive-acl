package network_entities

import (
	"strconv"

	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

func (f Flow) String() string {
	if f.Protocol == nil {
		return "protocol is nil"
	}
	switch f.Protocol.Title {
	case "icmp":
		return f.Src_iface + "->" + f.Dst_iface + " " + f.Protocol.Title + "://" + utils.IpToString(f.Src_ip) + " -> " + utils.IpToString(f.Dst_ip) + " (type: " + strconv.Itoa(f.Icmp_type) + ", code: " + strconv.Itoa(f.Icmp_code) + ")"
	case "tcp", "udp":
		return f.Src_iface + "->" + f.Dst_iface + " " + f.Protocol.Title + "://" + utils.IpToString(f.Src_ip) + ":" + strconv.Itoa(int(f.Src_port)) + " -> " + utils.IpToString(f.Dst_ip) + ":" + strconv.Itoa(int(f.Dst_port))
	default:
		return "unknown protocol"
	}
}
