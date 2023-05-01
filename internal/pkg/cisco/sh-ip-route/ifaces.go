package sh_ip_route

import (
	"errors"
	"log"
	"strings"

	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list/sh-run-pipe"
)

var ifaces map[string]string

func isIface(iface_name string) bool {
	_, ok := ifaces[iface_name]
	return ok
}

func findAllIfaceNames() (map[string]string, error) {

	iface_candidates := sh_run_pipe.Include("nameif").Exclude("no nameif")
	if len(iface_candidates) == 0 {
		error_message := "ERROR: no nameif found"
		log.Println(error_message)
		return nil, errors.New(error_message)
	}

	for _, iface_candidate := range iface_candidates {
		fields := strings.Fields(iface_candidate)
		if len(fields) < 2 {
			error_message := "ERROR: can't parse nameif"
			log.Println(error_message, ": ", iface_candidate)
			return nil, errors.New(error_message)
		}
		ifaces[strings.Fields(iface_candidate)[1]] = ""
	}

	return ifaces, nil
}
