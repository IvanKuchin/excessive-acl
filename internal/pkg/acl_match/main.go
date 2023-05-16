package aclmatch

import (
	"context"
	"fmt"

	app_context "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/app-context"
	cisco_asa_acg "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-group"
	cisco_asa_acl "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list"
	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
	"golang.org/x/sync/errgroup"
)

func getACLNamesByFlow(flow network_entities.Flow, app_ctx app_context.AppContext) (inbound_acl_name, outbound_acl_name string, err error) {
	for _, acg := range app_ctx.Access_groups {
		if acg.Iface == flow.Src_iface && acg.Direction == cisco_asa_acg.Inbound {
			inbound_acl_name = acg.Acl_name
		} else if acg.Iface == flow.Dst_iface && acg.Direction == cisco_asa_acg.Outbound {
			outbound_acl_name = acg.Acl_name
		}
	}
	return inbound_acl_name, outbound_acl_name, nil
}
func getACLsByFlow(flow network_entities.Flow, app_ctx app_context.AppContext) (inbound_acl, outbound_acl *cisco_asa_acl.Accesslist, err error) {
	inbound_acl_name, outbound_acl_name, err := getACLNamesByFlow(flow, app_ctx)
	if err != nil {
		return nil, nil, err
	}

	for i, acl := range app_ctx.Access_lists {
		if acl.Name == inbound_acl_name {
			inbound_acl = &app_ctx.Access_lists[i]
		} else if acl.Name == outbound_acl_name {
			outbound_acl = &app_ctx.Access_lists[i]
		}
	}
	return inbound_acl, outbound_acl, nil
}

func StartRoutines(num int, app_ctx app_context.AppContext) error {
	errs, _ := errgroup.WithContext(context.TODO())

	for i := 0; i < num; i++ {
		errs.Go(func() error {
			for flow := range app_ctx.Flows {
				if flow.Protocol == nil {
					continue
				}

				inbound_acl, outbound_acl, err := getACLsByFlow(flow, app_ctx)
				if err != nil {
					return err
				}

				if utils.GetLogLevel() == utils.Trace {
					fmt.Printf("flow: %s\n", flow)
					if inbound_acl != nil {
						fmt.Printf("\tinbound_acl: %s\n", inbound_acl.Name)
					}
					if outbound_acl != nil {
						fmt.Printf("\toutbound_acl: %s\n", outbound_acl.Name)
					}
				} else {
					fmt.Print(".")
				}

				if inbound_acl != nil {
					err = inbound_acl.AddFlow(flow)
					if err != nil {
						return err
					}
				}
				if outbound_acl != nil {
					err = outbound_acl.AddFlow(flow)
					if err != nil {
						return err
					}
				}
			}
			return nil

		})
	}

	return errs.Wait()
}
