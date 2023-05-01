package sh_ip_route

import (
	"errors"
	"fmt"

	"github.com/ivankuchin/excessive-acl/internal/utils"
)

func (re *routingEntry) getIface(ip uint32) (string, error) {
	if re.prefix.Start <= ip && ip <= re.prefix.Finish {
		for _, child := range re.children {
			if child.prefix.Start <= ip && ip <= child.prefix.Finish {
				iface, err := child.getIface(ip)
				if err != nil {
					return "", err
				}

				if iface == "" {
					return child.iface, nil
				} else {
					return iface, nil
				}
			}
		}
	}

	return "", nil
}

func (rt *RoutingTable) GetIface(ip uint32) (string, error) {
	for _, re := range rt.entry {
		if re.parent == nil {
			iface, err := re.getIface(ip)
			if err != nil {
				return "", err
			}
			if iface == "" {
				error_msg := "ERROR: no interface found for ip " + utils.IpToString(ip)
				fmt.Println(error_msg)
				return "", errors.New(error_msg)
			} else {
				return iface, nil
			}
		}
	}
	return "", nil
}
