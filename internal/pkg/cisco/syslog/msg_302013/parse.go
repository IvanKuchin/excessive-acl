package msg302013

import (
	"errors"
	"fmt"
	"strings"

	msg106023 "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/syslog/msg_106023"
	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
)

// example:
// %ASA-6-302013: Built inbound TCP connection 54 for outside:150.150.150.150/57346 (150.150.150.150/57346) to dmz:172.16.16.16/22 (123.123.123.10/22)
// %ASA-6-302013: Built outbound TCP connection 56 for outside:150.150.150.150/22 (150.150.150.150/22) to dmz:172.16.16.16/51624 (123.123.123.10/51624)
// %ASA-6-302013: Built {inbound|outbound} TCP connection number for interface :real-address /real-port (mapped-address/mapped-port ) [(idfw_user )] to interface :real-address /real-port (mapped-address/mapped-port ) [(idfw_user )] [(user )]
// %ASA-6-302015: Built {inbound|outbound} UDP connection number for interface :real_address /real_port (mapped_address/mapped_port ) [(idfw_user )] to interface :real_address /real_port (mapped_address/mapped_port ) [(idfw_user )] [(user )]
func Parse(fields []string) (network_entities.Flow, error) {
	fl := network_entities.Flow{Icmp_code: -1, Icmp_type: -1}

	// fmt.Printf("302013: %v\n", fields)

	if len(fields) < 11 {
		error_message := "ERROR: can't parse syslog message 302013/302015"
		fmt.Printf("%s (%s)\n", error_message, fields)
		return fl, errors.New(error_message)
	}

	proto, err := network_entities.GetProtoByName(strings.ToLower(fields[3]))
	if err != nil {
		return fl, err
	}

	fl.Protocol = proto[0]

	var src_idx, dst_idx int
	switch strings.ToLower(fields[2]) {
	case "inbound":
		src_idx = 7
		dst_idx = 10
	case "outbound":
		src_idx = 10
		dst_idx = 7
	default:
		error_message := "ERROR: can't parse syslog message 302013/302015, inbound/outbound not found"
		fmt.Printf("%s (%s)\n", error_message, fields)
		return fl, errors.New(error_message)
	}

	fl.Src_iface, fl.Src_ip, fl.Src_port, err = msg106023.ParseIfaceIPPort(fields[src_idx])
	if err != nil {
		return fl, err
	}
	fl.Dst_iface, fl.Dst_ip, fl.Dst_port, err = msg106023.ParseIfaceIPPort(fields[dst_idx])
	if err != nil {
		return fl, err
	}

	return fl, nil
}
