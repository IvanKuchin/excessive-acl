package ciscoasaaccessentry

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

func (ace *accessEntryCompiled) AddFlow(flow network_entities.Flow) error {
	if ace.m == nil {
		ace.m = &sync.Mutex{}
	}

	ace.m.Lock()
	defer ace.m.Unlock()
	ace.flows = append(ace.flows, flow)
	return nil
}

func (ace *accessEntryCompiled) MatchFlow(flow network_entities.Flow) (bool, error) {
	if ace.proto == nil {
		error_message := "ERROR: compiled access entry protocol is nil"
		fmt.Printf("%s\n", error_message)
		return false, errors.New(error_message)
	}
	if flow.Protocol == nil {
		error_message := "ERROR: flow protocol is nil"
		fmt.Printf("%s (%s)\n", error_message, flow)
		return false, errors.New(error_message)
	}
	if !ace.proto.Match(flow.Protocol) {
		return false, nil
	}

	if !(ace.src_addr_range.Start <= flow.Src_ip && flow.Src_ip <= ace.src_addr_range.Finish) {
		return false, nil
	}

	if !(ace.dst_addr_range.Start <= flow.Dst_ip && flow.Dst_ip <= ace.dst_addr_range.Finish) {
		return false, nil
	}

	switch ace.proto.Id {
	case 4: // ip
		return true, nil
	case 6, 17: // tcp, udp
		if ace.proto.ExactMatch(flow.Protocol) {
			// both protocols are TCP or UDP, so we ьгые check ports
			switch {
			case ace.src_port_range.finish == 0 && ace.dst_port_range.finish == 0:
				// both ports are 0, we don't need to check the flow
				return true, nil
			case ace.src_port_range.finish == 0 &&
				ace.dst_port_range.start <= port(flow.Dst_port) && port(flow.Dst_port) <= ace.dst_port_range.finish:
				// source port is 0, we don't need to check the flow
				return true, nil
			case ace.dst_port_range.finish == 0 &&
				ace.src_port_range.start <= port(flow.Src_port) && port(flow.Src_port) <= ace.src_port_range.finish:
				// destination port is 0, we don't need to check the flow
				return true, nil
			case ace.src_port_range.start <= port(flow.Src_port) && port(flow.Src_port) <= ace.src_port_range.finish &&
				ace.dst_port_range.start <= port(flow.Dst_port) && port(flow.Dst_port) <= ace.dst_port_range.finish:
				// both ports are not 0, we need to check both source and destination ports
				return true, nil
			default:
				return false, nil
			}
		}
		return true, nil
	case 1: // icmp
		if ace.proto.ExactMatch(flow.Protocol) {
			// both protocols are ICMP, so we can check ICMP types and codes
			switch {
			// both ICMP types and codes are -1, we don't need to check the flow
			case ace.icmp.icmp_code == -1 && ace.icmp.icmp_type == -1:
				return true, nil
			// ICMP code is not -1, so we need to check both ICMP type and code
			case ace.icmp.icmp_type == flow.Icmp_type && ace.icmp.icmp_code == -1:
				return true, nil
			// ICMP code is not -1, so we need to check both ICMP type and code
			case ace.icmp.icmp_type == flow.Icmp_type && ace.icmp.icmp_code == flow.Icmp_code:
				return true, nil

			default:
				return false, nil
			}
		} else {
			// one of protocols is IP, we don't need to check details
			return true, nil
		}
	}

	return true, nil
}

func (compiled accessEntryCompiled) String() string {
	var str1, str2 string

	str1 = fmt.Sprintf("%v %v %v-%v",
		compiled.action,
		compiled.proto.Title,
		utils.IpToString(compiled.src_addr_range.Start), utils.IpToString(compiled.src_addr_range.Finish),
	)
	switch {
	case compiled.icmp.icmp_code != -1 || compiled.icmp.icmp_type != -1:
		str2 = fmt.Sprintf("  %v-%v %v %v",
			utils.IpToString(compiled.dst_addr_range.Start), utils.IpToString(compiled.dst_addr_range.Finish),
			compiled.icmp.icmp_type, compiled.icmp.icmp_code,
		)
	case compiled.src_port_range.finish != 0 && compiled.dst_port_range.finish != 0:
		str2 = fmt.Sprintf(":%v-%v %v-%v:%v-%v",
			compiled.src_port_range.start, compiled.src_port_range.finish,
			utils.IpToString(compiled.dst_addr_range.Start), utils.IpToString(compiled.dst_addr_range.Finish),
			compiled.dst_port_range.start, compiled.dst_port_range.finish,
		)
	case compiled.src_port_range.finish != 0:
		str2 = fmt.Sprintf(":%v-%v %v-%v",
			compiled.src_port_range.start, compiled.src_port_range.finish,
			utils.IpToString(compiled.dst_addr_range.Start), utils.IpToString(compiled.dst_addr_range.Finish),
		)
	case compiled.dst_port_range.finish != 0:
		str2 = fmt.Sprintf(" %v-%v:%v-%v",
			utils.IpToString(compiled.dst_addr_range.Start), utils.IpToString(compiled.dst_addr_range.Finish),
			compiled.dst_port_range.start, compiled.dst_port_range.finish,
		)
	default:
		str2 = fmt.Sprintf(" %v-%v",
			utils.IpToString(compiled.dst_addr_range.Start), utils.IpToString(compiled.dst_addr_range.Finish),
		)

	}

	return str1 + str2
}

func (ace *accessEntryCompiled) getCapacity() (uint, error) {
	var src_ip_space, dst_ip_space uint
	var src_port_space, dst_port_space uint
	var icmp_type_space, icmp_code_space uint

	src_ip_space += uint(int(ace.src_addr_range.Finish) - int(ace.src_addr_range.Start) + 1)
	dst_ip_space += uint(int(ace.dst_addr_range.Finish) - int(ace.dst_addr_range.Start) + 1)

	if src_ip_space == 0x100000000 {
		src_ip_space = 1
	}
	if dst_ip_space == 0x100000000 {
		dst_ip_space = 1
	}

	switch ace.proto.Id {
	case 4: // ip
		return src_ip_space * dst_ip_space, nil
	case 6, 17: // tcp, udp
		if ace.src_port_range.finish == 0 {
			// most protocols uses ephemeral ports to source connections,
			// we do not take them into account
			src_port_space = 1
		} else {
			src_port_space += uint(ace.src_port_range.finish-ace.src_port_range.start) + 1
		}
		if ace.dst_port_range.finish == 0 {
			// if destination ports are not explicitely pointed out, means they probably forgotten
			// whole tcp port range (1-65535) is open
			dst_port_space += 65536
		} else {
			dst_port_space += uint(ace.dst_port_range.finish-ace.dst_port_range.start) + 1
		}
		return src_port_space * src_ip_space * dst_port_space * dst_ip_space, nil
	case 1: // icmp
		if ace.icmp_flows.icmp_type == 0 {
			// calculate ACE capacity
			if ace.icmp.icmp_type == -1 {
				icmp_type_space = 256
			} else {
				icmp_type_space = 1
			}
			if ace.icmp.icmp_code == -1 {
				icmp_code_space = 256
			} else {
				icmp_code_space = 1
			}
		} else {
			// calculate ICMP flows capacity
			icmp_type_space = uint(ace.icmp_flows.icmp_type)
			icmp_code_space = uint(ace.icmp_flows.icmp_code)
		}

		icmp_space := icmp_code_space * icmp_type_space
		ip_space := src_ip_space * dst_ip_space
		return ip_space * icmp_space, nil
	default:
		error_message := "ERROR: unknown protocol"
		fmt.Printf("%s (%v)\n", error_message, ace.proto)
		return 0, errors.New(error_message)
	}
}

func (ace *accessEntryCompiled) getFlowsUniqueSrcIPs() uint32 {
	var ips map[uint32]bool
	ips = make(map[uint32]bool)

	for _, flow := range ace.flows {
		ips[flow.Src_ip] = true
	}

	return uint32(len(ips))
}

func (ace *accessEntryCompiled) getFlowsUniqueDstIPs() uint32 {
	var ips map[uint32]bool
	ips = make(map[uint32]bool)

	for _, flow := range ace.flows {
		ips[flow.Dst_ip] = true
	}

	return uint32(len(ips))
}

func (ace *accessEntryCompiled) getFlowsUniqueSrcPorts() port {
	var ports map[uint32]bool
	ports = make(map[uint32]bool)

	for _, flow := range ace.flows {
		ports[uint32(flow.Src_port)] = true
	}

	return port(len(ports))
}

func (ace *accessEntryCompiled) getFlowsUniqueDstPorts() port {
	var ports map[uint32]bool
	ports = make(map[uint32]bool)

	for _, flow := range ace.flows {
		ports[uint32(flow.Dst_port)] = true
	}

	return port(len(ports))
}

func (ace *accessEntryCompiled) getFlowsUniqueICMPTypes() int {
	var types map[uint32]bool
	types = make(map[uint32]bool)

	for _, flow := range ace.flows {
		types[uint32(flow.Icmp_type)] = true
	}

	return len(types)
}

func (ace *accessEntryCompiled) getFlowsUniqueICMPCodes() int {
	var codes map[uint32]bool
	codes = make(map[uint32]bool)

	for _, flow := range ace.flows {
		codes[uint32(flow.Icmp_code)] = true
	}

	return len(codes)
}

func (ace *accessEntryCompiled) getFakeACE() (accessEntryCompiled, error) {
	fake_ace := accessEntryCompiled{
		action: ace.action,
		proto:  ace.proto,
		// src_addr_range: utils.AddressObject{Start: 1, Finish: ace.getFlowsUniqueSrcIPs()},
		// dst_addr_range: utils.AddressObject{Start: 1, Finish: ace.getFlowsUniqueDstIPs()},
	}

	if ace.src_addr_range.Start == 0 && ace.src_addr_range.Finish == 0xffffffff {
		fake_ace.src_addr_range = utils.AddressObject{Start: 0, Finish: 0xffffffff}
	} else {
		fake_ace.src_addr_range = utils.AddressObject{Start: 1, Finish: ace.getFlowsUniqueSrcIPs()}
	}
	if ace.dst_addr_range.Start == 0 && ace.dst_addr_range.Finish == 0xffffffff {
		fake_ace.dst_addr_range = utils.AddressObject{Start: 0, Finish: 0xffffffff}
	} else {
		fake_ace.dst_addr_range = utils.AddressObject{Start: 1, Finish: ace.getFlowsUniqueDstIPs()}
	}

	switch ace.proto.Id {
	case 4: // ip
		return fake_ace, nil
	case 6, 17: // tcp, udp
		fake_ace.src_port_range = port_range{start: 1, finish: ace.getFlowsUniqueSrcPorts()}
		fake_ace.dst_port_range = port_range{start: 1, finish: ace.getFlowsUniqueDstPorts()}
		return fake_ace, nil
	case 1: // icmp
		fake_ace.icmp_flows.icmp_type = ace.getFlowsUniqueICMPTypes()
		fake_ace.icmp_flows.icmp_code = ace.getFlowsUniqueICMPCodes()
		return fake_ace, nil
	}

	return fake_ace, nil
}

func (ace *accessEntryCompiled) getFlowsCapacity() (uint, error) {
	fake_ace, err := ace.getFakeACE()
	if err != nil {
		return 0, err
	}
	capacity, err := fake_ace.getCapacity()
	if err != nil {
		return 0, err
	}

	return capacity, nil
}

func (ace *accessEntryCompiled) Analyze() error {

	ace_space, err := ace.getCapacity()
	if err != nil {
		return err
	}
	fmt.Printf("\t ACE: capacity 0x%x, %v\n", ace_space, ace)

	flows_capacity, err := ace.getFlowsCapacity()
	if err != nil {
		return err
	}
	fmt.Printf("\t # of flows: %v, capacity: 0x%x, ACE capacity utilization(%%): %.3f\n", len(ace.flows), flows_capacity, float64(flows_capacity)/float64(ace_space)*100.0)
	for _, flow := range ace.flows {
		fmt.Printf("\t\t %v\n", flow)
	}

	return nil
}
