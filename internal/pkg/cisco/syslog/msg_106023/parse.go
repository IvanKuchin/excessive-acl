package msg106023

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

// input format: iface:ip
func parseIfaceIP(iface_ip string) (string, uint32, error) {
	var iface string
	var ip uint32
	var err error

	iface_ip_split := strings.Split(iface_ip, ":")
	if len(iface_ip_split) != 2 {
		error_message := "ERROR: can't parse iface_ip"
		fmt.Printf("%s (%s)\n", error_message, iface_ip)
		return iface, ip, errors.New(error_message)
	}
	iface = iface_ip_split[0]
	ip, err = utils.ParseIP(iface_ip_split[1])
	if err != nil {
		return iface, ip, err
	}
	return iface, ip, nil
}

// input format: iface:ip/port
func ParseIfaceIPPort(iface_ip_port string) (string, uint32, uint16, error) {
	var iface string
	var ip uint32
	var port uint16
	var err error

	iface_ip_port_split := strings.Split(iface_ip_port, "/")
	if len(iface_ip_port_split) != 2 {
		error_message := "ERROR: can't parse iface_ip_port"
		fmt.Printf("%s (%s)\n", error_message, iface_ip_port)
		return iface, ip, port, errors.New(error_message)
	}
	iface, ip, err = parseIfaceIP(iface_ip_port_split[0])
	if err != nil {
		return iface, ip, port, err
	}
	_port, err := strconv.ParseUint(iface_ip_port_split[1], 10, 16)
	if err != nil {
		error_message := "ERROR: can't parse port in iface_ip_port"
		fmt.Printf("%s (%s)\n", error_message, iface_ip_port)
		return iface, ip, port, errors.New(error_message)
	}
	return iface, ip, uint16(_port), nil
}

// example:
// %ASA-4-106023: Deny icmp src inside:10.10.9.9 dst outside:10.10.10.10 (type 8, code 0) by access-group "test" [0x0, 0x0]
// %ASA-4-106023: Deny tcp src inside:10.10.9.9/45306 dst outside:150.150.150.150/22 by access-group "inside_in" [0x6643b58b, 0x0]
func Parse(fields []string) (network_entities.Flow, error) {
	fl := network_entities.Flow{Icmp_code: -1, Icmp_type: -1}

	// fmt.Printf("106023: %v\n", fields)

	if len(fields) < 11 {
		error_message := "ERROR: can't parse syslog message 106023"
		fmt.Printf("%s (%s)\n", error_message, fields)
		return fl, errors.New(error_message)
	}

	proto, err := network_entities.GetProtoByName(strings.ToLower(fields[2]))
	if err != nil {
		return fl, err
	}

	fl.Protocol = proto[0]

	switch fl.Protocol.Title {
	case "icmp":

		fl.Src_iface, fl.Src_ip, err = parseIfaceIP(fields[4])
		if err != nil {
			return fl, err
		}
		fl.Dst_iface, fl.Dst_ip, err = parseIfaceIP(fields[6])
		if err != nil {
			return fl, err
		}
		fl.Icmp_type, err = strconv.Atoi(fields[8][:len(fields[8])-1])
		if err != nil {
			error_message := "ERROR: can't parse icmp type in a syslog message 106023"
			fmt.Printf("%s (%s)\n", error_message, fields)
			return fl, errors.New(error_message)
		}
		fl.Icmp_code, err = strconv.Atoi(fields[10][:len(fields[10])-1])
		if err != nil {
			error_message := "ERROR: can't parse icmp code in a syslog message 106023"
			fmt.Printf("%s (%s)\n", error_message, fields)
			return fl, errors.New(error_message)
		}
	case "tcp", "udp":
		fl.Src_iface, fl.Src_ip, fl.Src_port, err = ParseIfaceIPPort(fields[4])
		if err != nil {
			return fl, err
		}
		fl.Dst_iface, fl.Dst_ip, fl.Dst_port, err = ParseIfaceIPPort(fields[6])
		if err != nil {
			return fl, err
		}
	default:
		error_message := "ERROR: unknown protocol in a syslog message 106023"
		fmt.Printf("%s (%s)\n", error_message, fields)
		return fl, errors.New(error_message)
	}

	return fl, nil
}
