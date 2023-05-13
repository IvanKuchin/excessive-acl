package ciscoasaaccessentry

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

func tryToIdentifyAndParseServiceInsideACE(src_dst string, parsing_pos uint, fields []string, service_objects []serviceObject) (uint, error) {
	isItServiceHere, err := isServiceAtAPosition(parsing_pos, fields)
	if err != nil {
		return 0, err
	}
	if isItServiceHere {
		if service_objects != nil {
			if len(service_objects) == 1 {
				if service_objects[0].proto[0].Title == "tcp" || service_objects[0].proto[0].Title == "udp" || service_objects[0].proto[0].Title == "icmp" {

					parsing_pos, err = service_objects[0].parseTcpUdpIcmpServicesInTheMiddleOfAnACL(src_dst, parsing_pos, fields)
					if err != nil {
						return 0, err
					}
				} else {
					error_message := "protocol is not tcp or udp"
					log.Printf("ERROR: %s (%s) in %v\n", error_message, fields[2], fields)
					return 0, errors.New(error_message)
				}
			} else {
				error_message := "service object len is " + strconv.Itoa(len(service_objects)) + ", but expected to be 1."
				log.Printf("ERROR: %s in %v\n", error_message, fields)
				return 0, errors.New(error_message)
			}
		} else {
			error_message := "service object is nil, but expected to be not nil."
			log.Printf("ERROR: %s in %v\n", error_message, fields)
			return 0, errors.New(error_message)
		}
	}
	return parsing_pos, nil
}

func getProto(name string) ([]*network_entities.Protocol, error) {
	proto, err := network_entities.GetProtoByName(name)
	return proto, err
}

func getAction(action string) (action, error) {
	switch action {
	case "permit":
		return permit, nil
	case "deny":
		return deny, nil
	default:
		log.Printf("unknown action (%s) in ace\n", action)
		return 0, errors.New("unknown action")
	}
}

func (ace *AccessEntry) compileACE(act action, serviceObjects []serviceObject, srcAddresses, dstAddresses []utils.AddressObject) error {
	ace.compiled = []accessEntryCompiled{}

	for _, svcObj := range serviceObjects {
		for _, proto := range svcObj.proto {
			for _, srcAddr := range srcAddresses {
				for _, dstAddr := range dstAddresses {
					compiledEntry := accessEntryCompiled{
						action:         act,
						proto:          proto,
						src_addr_range: srcAddr,
						dst_addr_range: dstAddr,
						icmp:           icmp_type_code{-1, -1},
					}

					switch {
					case svcObj.icmp != nil:
						for _, icmp := range svcObj.icmp {
							compiledEntry.icmp = icmp
							ace.compiled = append(ace.compiled, compiledEntry)
						}

					case svcObj.src_port_range != nil && svcObj.dst_port_range != nil:
						for _, srcPort := range svcObj.src_port_range {
							for _, dstPort := range svcObj.dst_port_range {
								compiledEntry.src_port_range = srcPort
								compiledEntry.dst_port_range = dstPort
								ace.compiled = append(ace.compiled, compiledEntry)
							}
						}

					case svcObj.src_port_range != nil:
						for _, srcPort := range svcObj.src_port_range {
							compiledEntry.src_port_range = srcPort
							ace.compiled = append(ace.compiled, compiledEntry)
						}

					case svcObj.dst_port_range != nil:
						for _, dstPort := range svcObj.dst_port_range {
							compiledEntry.dst_port_range = dstPort
							ace.compiled = append(ace.compiled, compiledEntry)
						}
					default:
						ace.compiled = append(ace.compiled, compiledEntry)
					}
				}
			}
		}
	}

	return nil
}

func (ace *AccessEntry) parseExtended(fields []string) error {
	// --- action block
	action, err := getAction(fields[3])
	if err != nil {
		return err
	}

	// --- protocol and service object block
	parsing_pos, service_objects, err := getProtocolOrServiceObject(4, fields)
	if err != nil {
		return err
	}

	parsing_pos, src_address_objects, err := getAddressObjects(parsing_pos, fields)
	if err != nil {
		return err
	}

	parsing_pos, err = tryToIdentifyAndParseServiceInsideACE("src", parsing_pos, fields, service_objects)
	if err != nil {
		return err
	}

	parsing_pos, dst_address_objects, err := getAddressObjects(parsing_pos, fields)
	if err != nil {
		return err
	}

	parsing_pos, err = tryToIdentifyAndParseServiceInsideACE("dst", parsing_pos, fields, service_objects)
	if err != nil {
		return err
	}

	// --- compile ACE
	err = ace.compileACE(action, service_objects, src_address_objects, dst_address_objects)
	if err != nil {
		return err
	}

	// log.Printf("  action %v\n", action)
	// log.Printf("  service object:")
	// for _, obj := range service_objects {
	// 	obj.print()
	// }

	// log.Printf("  src addresses:\n")
	// for _, obj := range src_address_objects {
	// 	obj.print()
	// }

	// log.Printf("  dst addresses:\n")
	// for _, obj := range dst_address_objects {
	// 	obj.print()
	// }

	return nil
}

func (ace *AccessEntry) Print() {
	fmt.Printf("ACE: %s\n", ace.line)
	for _, compiled := range ace.compiled {
		fmt.Printf("  %s\n", compiled)
	}
}

func Parse(ace_text string) (AccessEntry, error) {
	var ace AccessEntry
	ace.line = ace_text

	fields := strings.Fields(ace_text)

	switch fields[2] {
	case "extended":
		err := ace.parseExtended(fields)
		if err != nil {
			return ace, err
		}
	case "remark":
	default:
		error_message := "ERROR: unknown ACE type"
		log.Printf("%s (%s) in %s\n", error_message, fields[2], ace_text)
		return ace, errors.New(error_message)
	}

	return ace, nil
}
