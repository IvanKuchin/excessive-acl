package ciscoasaaccessentry

import (
	"errors"
	"log"
	"strconv"
	"strings"

	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list/sh-run-pipe"
)

func isProtocolObjectGroup(name string) bool {
	object_group_text := sh_run_pipe.Exact("object-group protocol " + name)
	switch object_group_text.Len() {
	case 0:
		return false
	case 1:
		return true
	default:
		error_message := "found " + strconv.Itoa(int(object_group_text.Len())) + " instances of object-group protocol " + name
		log.Println("ERROR: ", error_message)
		return false
	}
}

// parse "object-group protocol xxx"
func parseProtocolObjectGroup(name string) (serviceObject, error) {
	var object_group serviceObject

	object_group_text := sh_run_pipe.SectionExact("object-group protocol " + name).Exclude("object-group protocol " + name).Exclude("description ")
	if object_group_text.Len() == 0 {
		error_message := "object-group protocol " + name + " is empty"
		log.Println("ERROR: ", error_message)
		return object_group, errors.New(error_message)
	}

	for _, object_group_line := range object_group_text {
		fields := strings.Fields(object_group_line)

		switch fields[0] {
		case "protocol-object":
			if len(fields) < 2 {
				error_message := "protocol-object must have at least 2 fields in it. protocol-object " + name + " is " + strconv.Itoa(len(fields)) + " fields."
				log.Printf("ERROR: %s", error_message)
				return object_group, errors.New(error_message)
			}

			proto, err := getProto(fields[1])
			if err != nil {
				return object_group, err
			}
			object_group.proto = append(object_group.proto, proto...)

		case "group-object":
			_so_slice, err := parseProtocolObjectGroup(fields[1])
			if err != nil {
				return object_group, err
			}
			object_group.proto = append(object_group.proto, _so_slice.proto...)

		default:
			error_message := "first keyword in object-group protocol " + name + " must be \"protocol-object\" or \"group-object\" (" + object_group_line + ")"
			log.Println("ERROR: ", error_message)
			return object_group, errors.New(error_message)
		}
	}

	return object_group, nil
}
