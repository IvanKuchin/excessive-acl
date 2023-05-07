package app_context

import (
	cisco_asa_acg "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-group"
	cisco_asa_acl "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list"
	sh_ip_route "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/sh-ip-route"
	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
)

type AppContext struct {
	Access_groups []cisco_asa_acg.Accessgroup
	Access_lists  []cisco_asa_acl.Accesslist
	Routing_table sh_ip_route.RoutingTable
	Flows         chan network_entities.Flow
}
