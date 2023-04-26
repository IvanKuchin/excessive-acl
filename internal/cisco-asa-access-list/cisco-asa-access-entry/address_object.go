package ciscoasaaccessentry

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"

	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/cisco-asa-access-list/sh-run-pipe"
)

func parseIP(ip_str string) (uint32, error) {

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

func parseMask(mask_str string) (uint32, error) {
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

func parseSubnet(parsing_pos uint, fields []string) (uint, addressObject, error) {
	var _address_object addressObject

	if len(fields) < int(parsing_pos+2) {
		error_string := "ERROR: not enough fields to parse subnet"
		log.Print(error_string, "(", fields, ")")
		return 0, _address_object, errors.New(error_string)
	}

	ip, err := parseIP(fields[parsing_pos])
	if err != nil {
		return 0, _address_object, err
	}

	mask, err := parseMask(fields[parsing_pos+1])
	if err != nil {
		return 0, _address_object, err
	}

	_address_object.start = ip & mask
	_address_object.finish = ip | ^mask

	return parsing_pos + 2, _address_object, nil
}

func parseFQDN(fqdn string) ([]addressObject, error) {
	var _address_objects []addressObject

	ips, err := net.LookupIP(fqdn)
	if err != nil {
		error_string := "ERROR: failed to resolve " + fqdn
		log.Print(error_string)
		return nil, errors.New(error_string)
	}

	for _, ip := range ips {
		if ip.To4() == nil {
			fmt.Printf("Skipping IPv6 address: %s in %s name resolution\n", ip.String(), fqdn)
			continue
		}
		_address_object := addressObject{start: binary.BigEndian.Uint32(ip.To4()), finish: binary.BigEndian.Uint32(ip.To4())}
		_address_objects = append(_address_objects, _address_object)
	}

	return _address_objects, nil
}

func parseAddressObjectContent(fields []string) ([]addressObject, error) {
	var _address_objects []addressObject

	switch fields[0] {
	case "fqdn":
		if len(fields) < 2 {
			error_string := "ERROR: not enough fields to parse fqdn in address object"
			log.Print(error_string, "(", fields, ")")
			return nil, errors.New(error_string)
		}

		_ao, err := parseFQDN(fields[1])
		if err != nil {
			return nil, err
		}
		_address_objects = append(_address_objects, _ao...)
		return _address_objects, nil
	case "host":
		if len(fields) < 2 {
			error_string := "ERROR: not enough fields to parse host in address object"
			log.Print(error_string, "(", fields, ")")
			return nil, errors.New(error_string)
		}

		ip, err := parseIP(fields[1])
		if err != nil {
			return nil, err
		}
		_address_objects = append(_address_objects, addressObject{start: ip, finish: ip})

		return _address_objects, nil
	case "subnet":
		if len(fields) < 3 {
			error_string := "ERROR: not enough fields to parse subnet in address object"
			log.Print(error_string, "(", fields, ")")
			return nil, errors.New(error_string)
		}

		_, _address_object, err := parseSubnet(1, fields)
		if err != nil {
			return nil, err
		}
		_address_objects = append(_address_objects, _address_object)

		return _address_objects, nil
	case "range":
		if len(fields) < 3 {
			error_string := "ERROR: not enough fields to parse range in address object"
			log.Print(error_string, "(", fields, ")")
			return nil, errors.New(error_string)
		}

		start, err := parseIP(fields[1])
		if err != nil {
			return nil, err
		}

		finish, err := parseIP(fields[2])
		if err != nil {
			return nil, err
		}

		_address_objects = append(_address_objects, addressObject{start: start, finish: finish})

		return _address_objects, nil
	default:
		error_string := "ERROR: failed to parse address object"
		log.Print(error_string, "(", fields, ")")
		return nil, errors.New(error_string)
	}
}

func parseAddressObject(name string) ([]addressObject, error) {
	address_object_text := sh_run_pipe.SectionExact("object network " + name).Exclude("object network " + name).Exclude("description ").Exclude(" nat ")
	if address_object_text.Len() != 1 {
		error_message := "object network must have only 1 line in it. object network " + name + " is " + strconv.Itoa(int(address_object_text.Len())) + " lines."
		log.Printf("ERROR: %s", error_message)
		return nil, errors.New(error_message)
	}

	address_object_line, err := address_object_text.Get(0)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(address_object_line)

	return parseAddressObjectContent(fields)
}

func parseAddressObjectGroup(name string) ([]addressObject, error) {
	var address_object_group []addressObject

	address_object_group_text := sh_run_pipe.SectionExact("object-group network " + name).Exclude("object-group network " + name).Exclude("description ")
	if address_object_group_text.Len() == 0 {
		error_message := "object-group address " + name + " is empty"
		log.Println("ERROR: ", error_message)
		return nil, errors.New(error_message)
	}

	for _, address_object_group_line := range address_object_group_text {
		fields := strings.Fields(address_object_group_line)

		switch fields[0] {
		case "network-object":
			if len(fields) < 2 {
				error_message := "address-object must have at least 2 fields in it. address-object " + name + " is " + strconv.Itoa(len(fields)) + " fields."
				log.Printf("ERROR: %s", error_message)
				return nil, errors.New(error_message)
			}

			switch fields[1] {
			case "object":
				if len(fields) != 3 {
					error_message := "address-object object must have 3 fields in it. address-object object " + name + " is " + strconv.Itoa(len(fields)) + " fields."
					log.Printf("ERROR: %s", error_message)
					return nil, errors.New(error_message)
				}

				_ao, err := parseAddressObject(fields[2])
				if err != nil {
					return nil, err
				}
				address_object_group = append(address_object_group, _ao...)
			case "host":
				if len(fields) != 3 {
					error_message := "address-object host must have 3 fields in it. address-object host " + name + " is " + strconv.Itoa(len(fields)) + " fields."
					log.Printf("ERROR: %s", error_message)
					return nil, errors.New(error_message)
				}

				_ao, err := parseAddressObjectContent(fields[1:])
				if err != nil {
					return nil, err
				}
				address_object_group = append(address_object_group, _ao...)
			default:
				if len(fields) < 3 {
					error_string := "ERROR: not enough fields to parse subnet in address object"
					log.Print(error_string, "(", fields, ")")
					return nil, errors.New(error_string)
				}

				_, _ao, err := parseSubnet(1, fields)
				if err != nil {
					return nil, err
				}

				address_object_group = append(address_object_group, _ao)
			}
		case "group-object":
			if len(fields) != 2 {
				error_message := "group-object must have 2 fields in it. group-object " + name + " is " + strconv.Itoa(len(fields)) + " fields."
				log.Printf("ERROR: %s", error_message)
				return nil, errors.New(error_message)
			}

			_aog, err := parseAddressObjectGroup(fields[1])
			if err != nil {
				return nil, err
			}
			address_object_group = append(address_object_group, _aog...)

		default:
			error_message := "address-object-group must have only network-object or group-object in it. address-object-group " + name + " is " + fields[0] + "."
			log.Printf("ERROR: %s", error_message)
			return nil, errors.New(error_message)
		}
	}

	return address_object_group, nil
}

func getAddressObjects(parsing_pos uint, fields []string) (uint, []addressObject, error) {
	var address_objects []addressObject

	switch fields[parsing_pos] {
	case "object":
		if len(fields) < int(parsing_pos+2) {
			error_string := "ERROR: not enough fields to get address name"
			log.Print(error_string, "(", fields, ")")
			return 0, nil, errors.New(error_string)
		}
		obj_name := fields[parsing_pos+1]
		_address_object, err := parseAddressObject(obj_name)
		if err != nil {
			return 0, nil, err
		}
		address_objects = append(address_objects, _address_object...)

		// --- set parsing position to a next block
		parsing_pos += 2

	case "object-group":
		if len(fields) < int(parsing_pos+2) {
			error_string := "ERROR: not enough fields to get network object-group name"
			log.Print(error_string, "(", fields, ")")
			return 0, nil, errors.New(error_string)
		}
		_address_objects, err := parseAddressObjectGroup(fields[parsing_pos+1])
		if err != nil {
			return 0, nil, err
		}
		address_objects = append(address_objects, _address_objects...)

		// --- set parsing position to a next block
		parsing_pos += 2

	case "any4":
		address_objects = append(address_objects, addressObject{0, 0xffffffff})

		// --- set parsing position to a next block
		parsing_pos += 1

	case "any":
		address_objects = append(address_objects, addressObject{0, 0xffffffff})

		// --- set parsing position to a next block
		parsing_pos += 1

	case "host":
		ip, err := parseIP(fields[parsing_pos+1])
		if err != nil {
			return 0, nil, err
		}
		address_objects = append(address_objects, addressObject{ip, ip})

		// --- set parsing position to a next block
		parsing_pos += 2

	case "any6":
		error_string := "ERROR: any6 not implemented as an address object"
		log.Print(error_string)
		return 0, nil, errors.New(error_string)

	case "any6-any":
		error_string := "ERROR: any6-any not implemented as an address object"
		log.Print(error_string)
		return 0, nil, errors.New(error_string)

	case "interface":
		error_string := "ERROR: interface not implemented as an address object"
		log.Print(error_string)
		return 0, nil, errors.New(error_string)

	default:
		var _address_object addressObject
		var err error
		parsing_pos, _address_object, err = parseSubnet(parsing_pos, fields)
		if err != nil {
			return 0, nil, err
		}
		address_objects = append(address_objects, _address_object)
	}

	return parsing_pos, address_objects, nil
}

func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func (a *addressObject) print() {
	ip1 := ipToString(a.start)
	ip2 := ipToString(a.finish)
	s := fmt.Sprintf("prefix: %v -> %v ", ip1, ip2)
	log.Print(s)
}
