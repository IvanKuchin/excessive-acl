package utils

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
)

func ParseIP(ip_str string) (uint32, error) {

	ipAddr, err := netip.ParseAddr(ip_str)
	if err != nil {
		error_string := "ERROR: failed to parse ip address"
		log.Print(error_string, "(", ip_str, ")")
		return 0, errors.New(error_string)
	}

	if ipAddr.Is6() {
		error_string := "ERROR: ipv6 not implemented"
		log.Print(error_string)
		return 0, errors.New(error_string)
	}

	octets := ipAddr.As4()
	return uint32(octets[0])<<24 + uint32(octets[1])<<16 + uint32(octets[2])<<8 + uint32(octets[3]), nil
}

func ParseMask(mask_str string) (uint32, error) {
	switch mask_str {
	case "0.0.0.0":
		return uint32(0)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0), nil
	case "128.0.0.0":
		return uint32(128)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0), nil
	case "192.0.0.0":
		return uint32(192)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0), nil
	case "224.0.0.0":
		return uint32(224)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0), nil
	case "240.0.0.0":
		return uint32(240)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0), nil
	case "248.0.0.0":
		return uint32(248)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0), nil
	case "252.0.0.0":
		return uint32(252)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0), nil
	case "254.0.0.0":
		return uint32(254)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0), nil
	case "255.0.0.0":
		return uint32(255)<<24 + uint32(0)<<16 + uint32(0)<<8 + uint32(0), nil
	case "255.128.0.0":
		return uint32(255)<<24 + uint32(128)<<16 + uint32(0)<<8 + uint32(0), nil
	case "255.192.0.0":
		return uint32(255)<<24 + uint32(192)<<16 + uint32(0)<<8 + uint32(0), nil
	case "255.224.0.0":
		return uint32(255)<<24 + uint32(224)<<16 + uint32(0)<<8 + uint32(0), nil
	case "255.240.0.0":
		return uint32(255)<<24 + uint32(240)<<16 + uint32(0)<<8 + uint32(0), nil
	case "255.248.0.0":
		return uint32(255)<<24 + uint32(248)<<16 + uint32(0)<<8 + uint32(0), nil
	case "255.252.0.0":
		return uint32(255)<<24 + uint32(252)<<16 + uint32(0)<<8 + uint32(0), nil
	case "255.254.0.0":
		return uint32(255)<<24 + uint32(254)<<16 + uint32(0)<<8 + uint32(0), nil
	case "255.255.0.0":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(0)<<8 + uint32(0), nil
	case "255.255.128.0":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(128)<<8 + uint32(0), nil
	case "255.255.192.0":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(192)<<8 + uint32(0), nil
	case "255.255.224.0":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(224)<<8 + uint32(0), nil
	case "255.255.240.0":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(240)<<8 + uint32(0), nil
	case "255.255.248.0":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(248)<<8 + uint32(0), nil
	case "255.255.252.0":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(252)<<8 + uint32(0), nil
	case "255.255.254.0":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(254)<<8 + uint32(0), nil
	case "255.255.255.0":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(0), nil
	case "255.255.255.128":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(128), nil
	case "255.255.255.192":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(192), nil
	case "255.255.255.224":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(224), nil
	case "255.255.255.240":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(240), nil
	case "255.255.255.248":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(248), nil
	case "255.255.255.252":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(252), nil
	case "255.255.255.254":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(254), nil
	case "255.255.255.255":
		return uint32(255)<<24 + uint32(255)<<16 + uint32(255)<<8 + uint32(255), nil
	default:
		error_string := "ERROR: failed to parse mask"
		log.Print(error_string, "(", mask_str, ")")
		return 0, errors.New(error_string)
	}
}

func ParseSubnet(parsing_pos uint, fields []string) (uint, AddressObject, error) {
	var _address_object AddressObject

	if len(fields) < int(parsing_pos+2) {
		error_string := "ERROR: not enough fields to parse subnet"
		log.Print(error_string, "(", fields, ")")
		return 0, _address_object, errors.New(error_string)
	}

	ip, err := ParseIP(fields[parsing_pos])
	if err != nil {
		return 0, _address_object, err
	}

	mask, err := ParseMask(fields[parsing_pos+1])
	if err != nil {
		return 0, _address_object, err
	}

	_address_object.Start = ip & mask
	_address_object.Finish = ip | ^mask

	return parsing_pos + 2, _address_object, nil
}

func IpToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func (a *AddressObject) print() {
	ip1 := IpToString(a.Start)
	ip2 := IpToString(a.Finish)
	s := fmt.Sprintf("prefix: %v -> %v ", ip1, ip2)
	log.Print(s)
}
