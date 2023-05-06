package syslog

import (
	"errors"
	"fmt"
	"strings"

	msg106023 "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/syslog/msg_106023"
	msg302013 "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/syslog/msg_302013"
	msg302020 "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/syslog/msg_302020"
	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
)

func parseRecord(record string, app_ctx AppContext) (network_entities.Flow, error) {
	var fl network_entities.Flow
	if len(record) == 0 {
		return fl, nil
	}

	fields1 := strings.Fields(record)
	fields2 := strings.Split(fields1[0], "-")

	if len(fields2) < 2 {
		error_message := "ERROR: can't parse record "
		fmt.Printf("%s (%s)\n", error_message, record)
		return fl, errors.New(error_message)
	}

	switch fields2[2] {
	case "302013:", "302015:":
		return msg302013.Parse(fields1)
	case "302020:":
		return msg302020.Parse(fields1, app_ctx.Routing_table)
	case "106023:":
		return msg106023.Parse(fields1)
	default:
		return fl, nil
	}
}
