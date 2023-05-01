package network_entities

import (
	"errors"
	"log"
	"strconv"
)

func getSingleProtoByName(name string) (*Protocol, error) {
	elem, ok := Protocols_map[name]
	if !ok {
		error_message := "ERROR: protocol (" + name + ") doesn't exists"
		log.Println(error_message)
		// utils.PrintStackTrace()
		return nil, errors.New(error_message)
	}
	return elem, nil
}

func GetProtoByName(name string) ([]*Protocol, error) {
	if name == "tcp-udp" {
		p1, err := getSingleProtoByName("tcp")
		if err != nil {
			return nil, err
		}
		p2, err := getSingleProtoByName("udp")
		if err != nil {
			return nil, err
		}
		return []*Protocol{p1, p2}, nil
	}

	p, err := getSingleProtoByName(name)
	if err != nil {
		return nil, err
	}
	return []*Protocol{p}, nil
}

func GetTCPPortByName(name string) (*TcpPorts, error) {
	elem, ok := tcp_ports_map[name]
	if !ok {
		error_message := "ERROR: named tcp port (" + name + ") doesn't exists"
		log.Println(error_message)
		// utils.PrintStackTrace()
		return nil, errors.New(error_message)
	}
	return elem, nil
}

func GetTcpPortFromString(str string) (int, error) {
	p, err := strconv.Atoi(str)
	if err != nil {
		port_struct, err := GetTCPPortByName(str)
		if err != nil {
			return 0, err
		}
		p = int(port_struct.Id)
	}

	return p, nil
}

func GetICMPTypeCodeByName(name string) (*IcmpTypeCodes, error) {
	elem, ok := icmp_type_codes_map[name]
	if !ok {
		error_message := "ERROR: named icmp type code (" + name + ") doesn't exists"
		log.Println(error_message)
		return nil, errors.New(error_message)
	}
	return elem, nil
}

func GetIcmpTypeCodeFromString(str string) (int, error) {
	p, err := strconv.Atoi(str)
	if err != nil {
		switch str {
		case "log":
			return -1, nil
		default:
			icmp_struct, err := GetICMPTypeCodeByName(str)
			if err != nil {
				return 0, err
			}
			p = int(icmp_struct.Id)
		}
	}

	return p, nil
}

func IsIcmpTypeCodeFromString(str string) bool {
	_, err := strconv.Atoi(str)
	if err != nil {
		_, ok := icmp_type_codes_map[str]
		if !ok {
			return false
		}
	}

	return true
}

// Compares if protocols matching
// parameters order is important (example: IP in ACL should match TCP traffic, but not vice versa)
// Input:
// _proto1 - ACL
// _proto2 - traffic
func (_proto1 *Protocol) IsProtoMatch(_proto2 *Protocol) bool {
	if _proto1.Id == _proto2.Id {
		return true
	}
	if (_proto1.Id == 4) && (_proto2.Id == 6) {
		return true
	}
	if (_proto1.Id == 4) && (_proto2.Id == 17) {
		return true
	}

	return false
}
