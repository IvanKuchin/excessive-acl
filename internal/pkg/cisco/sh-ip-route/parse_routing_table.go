package sh_ip_route

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

func isRecursiveRoute(fields []string) bool {
	for _, field := range fields {
		if field == "via" {
			return true
		}
	}
	return false
}

func parseNextHop(fields []string) (uint32, error) {
	for i, field := range fields {
		if field == "via" {
			ips := strings.Split(fields[i+1], ",")
			if len(ips) == 0 {
				error_message := "ERROR: can't split next hops by comma"
				fmt.Printf("%v: %v\n", error_message, fields)
				return 0, fmt.Errorf(error_message)
			}
			next_hop, err := utils.ParseIP(ips[0])
			if err != nil {
				return 0, err
			}
			return next_hop, nil
		}
	}
	error_message := "ERROR: via not found in the recursive route"
	fmt.Printf("%v: %v\n", error_message, fields)
	return 0, fmt.Errorf(error_message)
}

func parseRoutingEntry(f_content []string) ([]routingEntry, error) {
	var routing_entries []routingEntry

	for _, line := range f_content {
		fields := strings.Fields(line)
		if len(fields) > 2 {
			switch {
			case isIface(fields[len(fields)-1]):
				var routing_entry routingEntry

				_, _prefix, err := utils.ParseSubnet(1, fields)
				if err != nil {
					return nil, err
				}
				routing_entry.prefix = _prefix
				routing_entry.iface = fields[len(fields)-1]

				routing_entries = append(routing_entries, routing_entry)
			case isRecursiveRoute(fields):
				var routing_entry routingEntry

				_, _prefix, err := utils.ParseSubnet(1, fields)
				if err != nil {
					return nil, err
				}

				next_hop, err := parseNextHop(fields)
				if err != nil {
					return nil, err
				}
				routing_entry.prefix = _prefix
				routing_entry.next_hop = next_hop

				routing_entries = append(routing_entries, routing_entry)
			default:
				error_message := "ERROR: can't parse routing entry"
				fmt.Printf("%v: %v\n", error_message, line)
				// return nil, fmt.Errorf("%v: %v", error_message, line)
			}
		}
	}

	return routing_entries, nil
}

func (rt *RoutingTable) BuildTree() error {
	sort.Slice(rt.entry, func(i, j int) bool {
		subnet_i := rt.entry[i].prefix.Finish - rt.entry[i].prefix.Start
		subnet_j := rt.entry[j].prefix.Finish - rt.entry[j].prefix.Start
		return subnet_i > subnet_j
	})

	// print routing table
	// fmt.Println("--- Routing table")
	// for _, re := range rt.entry {
	// 	fmt.Println(&re)
	// }

	for i, _ := range rt.entry {
		for j := i - 1; j >= 0; j-- {
			_child := &rt.entry[i]
			_parent := &rt.entry[j]
			if _child.prefix.Start >= _parent.prefix.Start && _child.prefix.Finish <= _parent.prefix.Finish {
				_child.parent = _parent
				_parent.children = append(_parent.children, _child)
				break
			}
		}
	}

	return nil
}

func (rt *RoutingTable) fixUnknownIfaces() error {
	for i, _ := range rt.entry {
		if rt.entry[i].iface == "" {
			nh := rt.entry[i].next_hop
			iface, err := rt.GetIface(nh)
			if err != nil {
				return err
			}
			rt.entry[i].iface = iface
		}
	}

	return nil
}

func (rt *RoutingTable) PrintTree() {
	fmt.Println("--- Routing table")
	for _, re := range rt.entry {
		if re.parent == nil {
			re.printTree()
		}
	}
}

func (re *routingEntry) printTree() {
	if len(re.children) == 0 {
		return
	}

	fmt.Println("----")
	if re.parent == nil {
		fmt.Print("root ")
	}
	fmt.Println("parent: ", re)
	for _, child := range re.children {
		fmt.Println("child:", child)
	}

	for _, child := range re.children {
		child.printTree()
	}
}

func (re *routingEntry) String() string {
	if re.next_hop == 0 {
		return fmt.Sprintf("%v-%v %v", utils.IpToString(re.prefix.Start), utils.IpToString(re.prefix.Finish), re.iface)
	}

	return fmt.Sprintf("%v-%v via %v %v", utils.IpToString(re.prefix.Start), utils.IpToString(re.prefix.Finish), utils.IpToString(re.next_hop), re.iface)
}

func parseRoutingTable(f_content []string) (RoutingTable, error) {
	var routing_table RoutingTable

	_re, err := parseRoutingEntry(f_content)
	if err != nil {
		return routing_table, err
	}
	routing_table.entry = append(routing_table.entry, _re...)

	err = routing_table.BuildTree()
	if err != nil {
		return routing_table, err
	}

	err = routing_table.fixUnknownIfaces()
	if err != nil {
		return routing_table, err
	}

	return routing_table, nil
}
