package ciscoasaaccessentry

import (
	"errors"
	"fmt"

	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

func (ace *accessEntryCompiled) AddFlow(flow network_entities.Flow) error {
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
