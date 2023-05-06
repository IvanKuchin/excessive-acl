package msg302020

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	sh_ip_route "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/sh-ip-route"
	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

// input format: ip/port
func parseIPPort(iface_ip_port string) (uint32, uint16, error) {
	var ip uint32
	var port uint16
	var err error

	iface_ip_port_split := strings.Split(iface_ip_port, "/")
	if len(iface_ip_port_split) != 2 {
		error_message := "ERROR: can't parse iface_ip_port"
		fmt.Printf("%s (%s)\n", error_message, iface_ip_port)
		return ip, port, errors.New(error_message)
	}
	ip, err = utils.ParseIP(iface_ip_port_split[0])
	if err != nil {
		return ip, port, err
	}
	_port, err := strconv.ParseUint(iface_ip_port_split[1], 10, 16)
	if err != nil {
		error_message := "ERROR: can't parse port in iface_ip_port"
		fmt.Printf("%s (%s)\n", error_message, iface_ip_port)
		return ip, port, errors.New(error_message)
	}
	return ip, uint16(_port), nil
}

// example:
// %ASA-6-302020: Built outbound ICMP connection for faddr 10.10.10.10/0 gaddr 10.10.9.9/17411 laddr 10.10.9.9/17411 type 8 code 0
// %ASA-6-302020: Built inbound ICMP connection for faddr 150.150.150.150/4 gaddr 123.123.123.10/0 laddr 172.16.16.16/0 type 8 code 0
func Parse(fields []string, routing_table sh_ip_route.RoutingTable) (network_entities.Flow, error) {
	fl := network_entities.Flow{Icmp_code: -1, Icmp_type: -1}

	// fmt.Printf("302020: %v\n", fields)

	if len(fields) < 16 {
		error_message := "ERROR: can't parse syslog message 302020"
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
		dst_idx = 11
	case "outbound":
		src_idx = 11
		dst_idx = 7
	default:
		error_message := "ERROR: can't parse syslog message 302020, inbound/outbound not found"
		fmt.Printf("%s (%s)\n", error_message, fields)
		return fl, errors.New(error_message)
	}

	fl.Src_ip, fl.Src_port, err = parseIPPort(fields[src_idx])
	if err != nil {
		return fl, err
	}
	fl.Dst_ip, fl.Dst_port, err = parseIPPort(fields[dst_idx])
	if err != nil {
		return fl, err
	}

	// find iface by ip
	fl.Src_iface, err = routing_table.GetIface(fl.Src_ip)
	if err != nil {
		return fl, err
	}
	fl.Dst_iface, err = routing_table.GetIface(fl.Dst_ip)
	if err != nil {
		return fl, err
	}

	// parse icmp type and code
	fl.Icmp_type, err = strconv.Atoi(fields[13])
	if err != nil {
		error_message := "ERROR: can't parse icmp type in syslog message 302020"
		fmt.Printf("%s (%s)\n", error_message, fields)
		return fl, err
	}

	fl.Icmp_code, err = strconv.Atoi(fields[15])
	if err != nil {
		error_message := "ERROR: can't parse icmp code in syslog message 302020"
		fmt.Printf("%s (%s)\n", error_message, fields)
		return fl, err
	}

	return fl, nil
}
