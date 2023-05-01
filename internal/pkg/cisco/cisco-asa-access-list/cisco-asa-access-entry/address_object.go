package ciscoasaaccessentry

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list/sh-run-pipe"
	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

func parseFQDN(fqdn string) ([]utils.AddressObject, error) {
	var _address_objects []utils.AddressObject

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
		_address_object := utils.AddressObject{Start: binary.BigEndian.Uint32(ip.To4()), Finish: binary.BigEndian.Uint32(ip.To4())}
		_address_objects = append(_address_objects, _address_object)
	}

	return _address_objects, nil
}

func parseAddressObjectContent(fields []string) ([]utils.AddressObject, error) {
	var _address_objects []utils.AddressObject

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

		ip, err := utils.ParseIP(fields[1])
		if err != nil {
			return nil, err
		}
		_address_objects = append(_address_objects, utils.AddressObject{Start: ip, Finish: ip})

		return _address_objects, nil
	case "subnet":
		if len(fields) < 3 {
			error_string := "ERROR: not enough fields to parse subnet in address object"
			log.Print(error_string, "(", fields, ")")
			return nil, errors.New(error_string)
		}

		_, _address_object, err := utils.ParseSubnet(1, fields)
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

		start, err := utils.ParseIP(fields[1])
		if err != nil {
			return nil, err
		}

		finish, err := utils.ParseIP(fields[2])
		if err != nil {
			return nil, err
		}

		_address_objects = append(_address_objects, utils.AddressObject{Start: start, Finish: finish})

		return _address_objects, nil
	default:
		error_string := "ERROR: failed to parse address object"
		log.Print(error_string, "(", fields, ")")
		return nil, errors.New(error_string)
	}
}

func parseAddressObject(name string) ([]utils.AddressObject, error) {
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

func parseAddressObjectGroup(name string) ([]utils.AddressObject, error) {
	var address_object_group []utils.AddressObject

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

				_, _ao, err := utils.ParseSubnet(1, fields)
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

func getAddressObjects(parsing_pos uint, fields []string) (uint, []utils.AddressObject, error) {
	var address_objects []utils.AddressObject

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
		address_objects = append(address_objects, utils.AddressObject{Start: 0, Finish: 0xffffffff})

		// --- set parsing position to a next block
		parsing_pos += 1

	case "any":
		address_objects = append(address_objects, utils.AddressObject{Start: 0, Finish: 0xffffffff})

		// --- set parsing position to a next block
		parsing_pos += 1

	case "host":
		ip, err := utils.ParseIP(fields[parsing_pos+1])
		if err != nil {
			return 0, nil, err
		}
		address_objects = append(address_objects, utils.AddressObject{Start: ip, Finish: ip})

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
		var _address_object utils.AddressObject
		var err error
		parsing_pos, _address_object, err = utils.ParseSubnet(parsing_pos, fields)
		if err != nil {
			return 0, nil, err
		}
		address_objects = append(address_objects, _address_object)
	}

	return parsing_pos, address_objects, nil
}
