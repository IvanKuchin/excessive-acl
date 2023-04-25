package ciscoasaaccessentry

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/cisco-asa-access-list/sh-run-pipe"
	"github.com/ivankuchin/excessive-acl/internal/network_entities"
)

// evaluate if service object tcp/udp/tcp-udp is at a position
func isServiceAtAPositionTCPUDP(name string) (bool, error) {
	service_object_text := sh_run_pipe.Include("object-group service " + name + " ")
	if service_object_text.Len() == 0 {
		return false, nil
	}
	if service_object_text.Len() != 1 {
		error_message := "found " + strconv.Itoa(int(service_object_text.Len())) + " object-group services " + name + ", expected 1."
		log.Printf("ERROR: %s", error_message)
		return false, errors.New(error_message)
	}

	s, err := service_object_text.Get(0)
	if err != nil {
		return false, err
	}

	fields := strings.Fields(s)
	if len(fields) < 4 {
		error_message := "not enough tokens in object-group service " + name + ". Expected at least 4, got " + strconv.Itoa(len(fields)) + "."
		log.Printf("ERROR: %s %v\n", error_message, fields)
		return false, errors.New(error_message)
	}

	proto := fields[3]
	switch proto {
	case "tcp", "udp", "tcp-udp":
		return true, nil
	default:
		error_message := "unexpected protocol " + proto + " in object-group service " + name + ". Expected tcp, udp or tcp-udp."
		log.Printf("ERROR: %s %v\n", error_message, fields)
		return false, errors.New(error_message)
	}
}

func isServiceAtAPosition(parsing_pos uint, fields []string) (bool, error) {
	if len(fields) <= int(parsing_pos) {
		return false, nil
	}

	switch fields[parsing_pos] {
	case "eq", "lt", "gt", "range", "neq":
		return true, nil
	case "object-group":
		if len(fields) <= (int(parsing_pos) + 1) {
			error_message := "not enough tokens in object group "
			log.Printf("ERROR: %s %v\n", error_message, fields)
			return false, errors.New(error_message)
		}

		return isServiceAtAPositionTCPUDP(fields[parsing_pos+1])
	default:
		if isIcmpTypeCodeAtAPosition(parsing_pos, fields) {
			return true, nil
		}

		return false, nil
	}
}

func parsePortRange(parsing_pos uint, fields []string, proto *network_entities.Protocol) (uint, []port_range, error) {
	var _port_range []port_range

	switch fields[parsing_pos] {
	case "eq":
		{
			if len(fields) > int(parsing_pos+1) {
				parsing_pos += 1
				p, err := network_entities.GetTcpPortFromString(fields[parsing_pos])
				if err != nil {
					return 0, nil, err
				}

				var pr = port_range{start: port(p), finish: port(p)}
				_port_range = append(_port_range, pr)

				parsing_pos += 1
			} else {
				error_message := "not enough tokens in port range "
				log.Printf("ERROR: %s %v\n", error_message, fields)
				return 0, nil, errors.New(error_message)
			}
		}
	case "lt":
		{
			if len(fields) > int(parsing_pos+1) {
				parsing_pos += 1
				p, err := network_entities.GetTcpPortFromString(fields[parsing_pos])
				if err != nil {
					return 0, nil, err
				}

				var pr = port_range{start: port(0), finish: port(p - 1)}
				_port_range = append(_port_range, pr)

				parsing_pos += 1
			} else {
				error_message := "not enough tokens in port range "
				log.Printf("ERROR: %s %v\n", error_message, fields)
				return 0, nil, errors.New(error_message)
			}
		}
	case "gt":
		{
			if len(fields) > int(parsing_pos+1) {
				parsing_pos += 1
				p, err := network_entities.GetTcpPortFromString(fields[parsing_pos])
				if err != nil {
					return 0, nil, err
				}

				var pr = port_range{start: port(p + 1), finish: port(65535)}
				_port_range = append(_port_range, pr)

				parsing_pos += 1
			} else {
				error_message := "not enough tokens in port range "
				log.Printf("ERROR: %s %v\n", error_message, fields)
				return 0, nil, errors.New(error_message)
			}
		}
	case "range":
		{
			if len(fields) > int(parsing_pos+2) {
				parsing_pos += 1
				p1, err := network_entities.GetTcpPortFromString(fields[parsing_pos])
				if err != nil {
					return 0, nil, err
				}
				p2, err := network_entities.GetTcpPortFromString(fields[parsing_pos+1])
				if err != nil {
					return 0, nil, err
				}

				var pr = port_range{start: port(p1), finish: port(p2)}
				_port_range = append(_port_range, pr)

				parsing_pos += 2
			} else {
				error_message := "not enough tokens in port range "
				log.Printf("ERROR: %s %v\n", error_message, fields)
				return 0, nil, errors.New(error_message)
			}
		}
	case "neq":
		{
			if len(fields) > int(parsing_pos+1) {
				parsing_pos += 1
				p, err := network_entities.GetTcpPortFromString(fields[parsing_pos])
				if err != nil {
					return 0, nil, err
				}

				var pr = []port_range{{start: port(0), finish: port(p - 1)}, {start: port(p + 1), finish: port(65535)}}
				_port_range = append(_port_range, pr...)

				parsing_pos += 1
			} else {
				error_message := "not enough tokens in port range "
				log.Printf("ERROR: %s %v\n", error_message, fields)
				return 0, nil, errors.New(error_message)
			}
		}

	}

	return parsing_pos, _port_range, nil
}

func parsePortGroup(name string) ([]port_range, error) {
	var _port_range []port_range

	// get the object group
	service_object_text := sh_run_pipe.Section("object-group service " + name + " ").Exclude("object-group service " + name).Exclude("description ")

	for i := uint(0); i < service_object_text.Len(); i++ {
		service_object_line, err := service_object_text.Get(i)
		if err != nil {
			return nil, err
		}

		fields := strings.Fields(service_object_line)
		if len(fields) < 2 {
			error_message := "not enough tokens in port-object #" + strconv.Itoa(int(i)) + " of object-group service " + name + ""
			log.Printf("ERROR: %s %v\n", error_message, fields)
			return nil, errors.New(error_message)
		}

		switch fields[0] {
		case "port-object":
			_, _pr, err := parsePortRange(1, fields, nil)
			if err != nil {
				return nil, err
			}

			_port_range = append(_port_range, _pr...)
		case "group-object":
			_pr, err := parsePortGroup(fields[1])
			if err != nil {
				return nil, err
			}

			_port_range = append(_port_range, _pr...)
		default:
			error_message := "unknown token(" + fields[0] + ") in object-group service " + name
			log.Printf("ERROR: %s %v\n", error_message, fields)
			return nil, errors.New(error_message)
		}
	}
	return _port_range, nil
}

func parseIcmpTypeCode(parsing_pos uint, fields []string) (uint, []icmp_type_code, error) {
	var _icmp = []icmp_type_code{{icmp_type: -1, icmp_code: -1}}

	if len(fields) > int(parsing_pos) {
		switch fields[parsing_pos] {
		default:
			p1, err := network_entities.GetIcmpTypeCodeFromString(fields[parsing_pos])
			if err != nil {
				return 0, nil, err
			}
			parsing_pos += 1
			_icmp[0].icmp_type = p1
		}
	}

	if len(fields) > int(parsing_pos) {
		p2, err := network_entities.GetIcmpTypeCodeFromString(fields[parsing_pos])
		if err != nil {
			return 0, nil, err
		}
		parsing_pos += 1
		_icmp[0].icmp_code = p2
	}

	return parsing_pos, _icmp, nil
}

// check if the field is a valid icmp type
// if icmp type is valid, return true
// example: "echo-reply"
func isIcmpTypeCodeAtAPosition(parsing_pos uint, fields []string) bool {
	// we get to check only icmp type no need to check icmp code
	if len(fields) > int(parsing_pos) {
		p1 := network_entities.IsIcmpTypeCodeFromString(fields[parsing_pos])
		if p1 == true {
			return true
		}
	}

	return false
}

// parse service object content
// input should not include keywords "service-object object" or "service"
// example1:
// object service ICMP
//
//	service icmp echo-reply <---- keyword "service" should be removed
//
// example2:
// object-group service OMNI-PORTS
//
//	service-object tcp-udp destination range 1 20  <---- keyword "service-object" should be removed
//
// example3:
// object-group service OMNI-PORTS
//
//	service-object object NTP  <---- keywords "service-object object" should be removed
func parseServiceObjectContent(fields []string) (*serviceObject, error) {
	var service_object serviceObject

	// --- protocol parsing
	protocols, err := network_entities.GetProtoByName(fields[0])
	if err != nil {
		return nil, err
	}
	service_object.proto = append(service_object.proto, protocols...)

	// --- if single protocol in the list, then it will be it
	// --- it it is tcp-udp, then it will be a tcp
	proto := protocols[0]

	if ((proto.Title == "tcp") || (proto.Title == "udp")) && (len(fields) > 1) {
		var parsing_pos uint
		parsing_pos = 1

		if len(fields) > int(parsing_pos) {
			// --- source port parsing
			if fields[parsing_pos] == "source" {
				var _port_range []port_range

				parsing_pos, _port_range, err = parsePortRange(parsing_pos+1, fields, proto)
				if err != nil {
					return nil, err
				}
				service_object.src_port_range = append(service_object.src_port_range, _port_range...)

			}
		}

		if len(fields) > int(parsing_pos) {
			// --- destination port parsing
			if fields[parsing_pos] == "destination" {
				var _port_range []port_range

				parsing_pos, _port_range, err = parsePortRange(parsing_pos+1, fields, proto)
				if err != nil {
					return nil, err
				}
				service_object.dst_port_range = append(service_object.dst_port_range, _port_range...)

			}
		}
	}
	if (proto.Title == "icmp") && (len(fields) > 1) {
		var parsing_pos uint
		parsing_pos = 1

		if len(fields) == 1 {
			service_object.icmp = append(service_object.icmp, icmp_type_code{icmp_type: -1, icmp_code: -1})
		} else if len(fields) > 1 {
			var _icmp []icmp_type_code
			parsing_pos, _icmp, err = parseIcmpTypeCode(parsing_pos, fields)
			if err != nil {
				return nil, err
			}
			service_object.icmp = append(service_object.icmp, _icmp...)
		}

	}

	return &service_object, nil
}

func parseServiceObject(name string) (*serviceObject, error) {

	service_object_text := sh_run_pipe.SectionExact("object service " + name).Exclude("object service " + name).Exclude("description ")
	if service_object_text.Len() != 1 {
		error_message := "object service must have only 1 line in it. object service " + name + " is " + strconv.Itoa(int(service_object_text.Len())) + " lines."
		log.Printf("ERROR: %s", error_message)
		return nil, errors.New(error_message)
	}
	service_object_line, err := service_object_text.Get(0)
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(service_object_line)

	if fields[0] != "service" {
		error_message := "first keyword in object service " + name + " must be \"service\" (" + service_object_line + ")"
		log.Println("ERROR: ", error_message)
		return nil, errors.New(error_message)
	}

	return parseServiceObjectContent(fields[1:])
}

func isServiceObjectGroup(name string) bool {
	service_object_group_text := sh_run_pipe.Exact("object-group service " + name)
	switch service_object_group_text.Len() {
	case 0:
		return false
	case 1:
		return true
	default:
		error_message := "found " + strconv.Itoa(int(service_object_group_text.Len())) + " instances of object-group service " + name
		log.Println("ERROR: ", error_message)
		return false
	}
}

// parse "object-group service xxx"
func parseServiceObjectGroup(name string) ([]serviceObject, error) {
	var service_object_group []serviceObject

	service_object_group_text := sh_run_pipe.SectionExact("object-group service " + name).Exclude("object-group service " + name).Exclude("description ")
	if service_object_group_text.Len() == 0 {
		error_message := "object-group service " + name + " is empty"
		log.Println("ERROR: ", error_message)
		return nil, errors.New(error_message)
	}

	for _, service_object_group_line := range service_object_group_text {
		fields := strings.Fields(service_object_group_line)

		switch fields[0] {
		case "service-object":
			if len(fields) < 2 {
				error_message := "service-object must have at least 2 fields in it. service-object " + name + " is " + strconv.Itoa(len(fields)) + " fields."
				log.Printf("ERROR: %s", error_message)
				return nil, errors.New(error_message)
			}

			switch fields[1] {
			case "object":
				{
					if len(fields) != 3 {
						error_message := "service-object object must have 3 fields in it. service-object object " + name + " is " + strconv.Itoa(len(fields)) + " fields."
						log.Printf("ERROR: %s", error_message)
						return nil, errors.New(error_message)
					}

					_so, err := parseServiceObject(fields[2])
					if err != nil {
						return nil, err
					}
					service_object_group = append(service_object_group, *_so)
				}
			default:
				{
					_so, err := parseServiceObjectContent(fields[1:])
					if err != nil {
						return nil, err
					}
					service_object_group = append(service_object_group, *_so)
				}
			}
		case "group-object":
			_so_slice, err := parseServiceObjectGroup(fields[1])
			if err != nil {
				return nil, err
			}
			service_object_group = append(service_object_group, _so_slice...)
		default:
			error_message := "first keyword in object-group service " + name + " must be \"service-object\" or \"group-object\" (" + service_object_group_line + ")"
			log.Println("ERROR: ", error_message)
			return nil, errors.New(error_message)
		}
	}

	return service_object_group, nil
}

// parse protocol id or service object at the start of the ACE.
// access-list xxx extended permit --> tcp <-- object-group xxx object-group xxx
// access-list xxx extended permit --> object xxx <-- object-group xxx object-group xxx
// access-list xxx extended permit --> object-group xxx <-- object-group xxx object-group xxx
func getProtocolOrServiceObject(parsing_pos uint, fields []string) (uint, []serviceObject, error) {
	var service_objects []serviceObject

	switch fields[parsing_pos] {
	case "object":
		_service_object, err := parseServiceObject(fields[parsing_pos+1])
		if err != nil {
			return 0, nil, err
		}
		service_objects = append(service_objects, *_service_object)

		// set parsing position to a next block
		parsing_pos += 2

	case "object-group":
		if len(fields) < int(parsing_pos+2) {
			error_message := "object-group must have at least 2 additional fields in it. object-group is " + strconv.Itoa(len(fields)) + " fields."
			log.Printf("ERROR: %s", error_message)
			return 0, nil, errors.New(error_message)
		}

		switch {
		case isServiceObjectGroup(fields[parsing_pos+1]):
			_service_objects, err := parseServiceObjectGroup(fields[parsing_pos+1])
			if err != nil {
				return 0, nil, err
			}
			service_objects = append(service_objects, _service_objects...)

			// set parsing position to a next block
			parsing_pos += 2

		case isProtocolObjectGroup(fields[parsing_pos+1]):
			_service_object, err := parseProtocolObjectGroup(fields[parsing_pos+1])
			if err != nil {
				return 0, nil, err
			}
			service_objects = append(service_objects, _service_object)

			// set parsing position to a next block
			parsing_pos += 2

		default:
			error_message := "unknown type of object-group " + fields[parsing_pos+1]
			log.Printf("ERROR: %s", error_message)
			return 0, nil, errors.New(error_message)
		}

	default:
		var _service_object serviceObject
		_protocols, err := getProto(fields[parsing_pos])
		if err != nil {
			return 0, nil, err
		}
		_service_object.proto = append(_service_object.proto, _protocols...)
		service_objects = append(service_objects, _service_object)

		// set parsing position to a next block
		parsing_pos += 1
	}

	return parsing_pos, service_objects, nil
}

func (so *serviceObject) print() {
	var s string
	s = "proto: "
	for _, p := range so.proto {
		s += fmt.Sprintf("%v ", *p)
	}
	s += fmt.Sprintf("src_port_range: %v ", so.src_port_range)
	s += fmt.Sprintf("dst_port_range: %v ", so.dst_port_range)
	s += fmt.Sprintf("icmp: %v ", so.icmp)
	log.Print(s)
}

// parse protocol id or service object in the middle and at the end of the ACE.
// access-list xxx extended permit tcp              object-group xxx --> eq 80 <--       object-group xxx --> eq 80 <--
// access-list xxx extended permit object xxx       object-group xxx --> range 80 81 <-- object-group xxx --> object-group some-ports <--
// access-list xxx extended permit object-group xxx object-group xxx                     object-group xxx --> neq 80 <--
func (so *serviceObject) parseTcpUdpIcmpServicesInTheMiddleOfAnACL(src_dst string, parsing_pos uint, fields []string) (uint, error) {
	var _pr []port_range
	var _icmp []icmp_type_code
	var err error

	if so.proto == nil {
		error_message := "tcp/udp/icmp service must be preceded by a protocol"
		log.Println("ERROR: ", error_message)
		return 0, errors.New(error_message)
	}

	switch so.proto[0].Title {
	case "tcp", "udp":
		switch fields[parsing_pos] {
		case "eq", "lt", "gt", "range", "neq":
			parsing_pos, _pr, err = parsePortRange(parsing_pos, fields, nil)
			if err != nil {
				return 0, err
			}

			if src_dst == "src" {
				so.src_port_range = append(so.src_port_range, _pr...)
			} else {
				so.dst_port_range = append(so.dst_port_range, _pr...)
			}

			return parsing_pos, nil
		case "object-group":
			_pr, err = parsePortGroup(fields[parsing_pos+1])
			if err != nil {
				return 0, err
			}
			parsing_pos += 2

			switch src_dst {
			case "src":
				so.src_port_range = append(so.src_port_range, _pr...)
			case "dst":
				so.dst_port_range = append(so.dst_port_range, _pr...)
			default:
				error_message := "tcp/udp service must be src or dst"
				log.Println("ERROR: ", error_message)
				return 0, errors.New(error_message)
			}

			return parsing_pos, nil
		default:
			error_message := "tcp/udp/icmp service must be eq, lt, gt, range, neq, or object-group (" + fields[parsing_pos] + ")"
			log.Println("ERROR: ", error_message)
			return 0, errors.New(error_message)
		}
	case "icmp":
		if src_dst == "dst" {
			parsing_pos, _icmp, err = parseIcmpTypeCode(parsing_pos, fields)
			if err != nil {
				return 0, err
			}

			so.icmp = append(so.icmp, _icmp...)

			return parsing_pos, nil
		} else {
			error_message := "icmp service must be dst only"
			log.Printf("ERROR: %s (%v)", error_message, fields)
			return 0, errors.New(error_message)
		}
	default:
		error_message := "unknonwn so.proto[0] " + so.proto[0].Title
		log.Println("ERROR: ", error_message)
		return 0, errors.New(error_message)
	}
}
