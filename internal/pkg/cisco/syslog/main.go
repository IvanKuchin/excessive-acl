package syslog

import (
	"bufio"
	"context"
	"fmt"
	"os"

	cisco_asa_acg "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-group"
	cisco_asa_acl "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list"
	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
	"golang.org/x/sync/errgroup"
)

var records chan string

func init() {
	records = make(chan string, 100)
}

func getACLNamessByFlow(flow network_entities.Flow, app_ctx AppContext) (inbound_acl_name, outbound_acl_name string, err error) {
	for _, acg := range app_ctx.Access_groups {
		if acg.Iface == flow.Src_iface && acg.Direction == cisco_asa_acg.Inbound {
			inbound_acl_name = acg.Acl_name
		} else if acg.Iface == flow.Dst_iface && acg.Direction == cisco_asa_acg.Outbound {
			outbound_acl_name = acg.Acl_name
		}
	}
	return inbound_acl_name, outbound_acl_name, nil
}
func getACLsByFlow(flow network_entities.Flow, app_ctx AppContext) (inbound_acl, outbound_acl *cisco_asa_acl.Accesslist, err error) {
	inbound_acl_name, outbound_acl_name, err := getACLNamessByFlow(flow, app_ctx)
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

func startReaders(ctx context.Context, app_ctx AppContext, count int) error {
	errs, ctx := errgroup.WithContext(ctx)

	fmt.Printf("--- Syslog parsing (count=%d)\n", count)

	for i := 0; i < count; i++ {
		errs.Go(func() error {
			for record := range records {
				flow, err := parseRecord(record, app_ctx)
				if err != nil {
					return err
				}
				if flow.Protocol == nil {
					continue
				}

				inbound_acl, outbound_acl, err := getACLsByFlow(flow, app_ctx)
				if err != nil {
					return err
				}

				fmt.Printf("flow: %s\n", flow)
				if inbound_acl != nil {
					fmt.Printf("\tinbound_acl: %s\n", inbound_acl.Name)
				}
				if outbound_acl != nil {
					fmt.Printf("\toutbound_acl: %s\n", outbound_acl.Name)
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

func load(in_file string) error {
	readFile, err := os.Open(in_file)
	if err != nil {
		fmt.Println("ERROR:", err)
		return err
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	go func() {
		defer close(records)
		defer readFile.Close()

		for fileScanner.Scan() {
			record := fileScanner.Text()
			records <- record
		}
	}()

	return nil
}

func Fit(app_ctx AppContext, in_file string) error {
	err := load(in_file)
	if err != nil {
		return err
	}

	err = startReaders(context.Background(), app_ctx, 1)
	if err != nil {
		return err
	}

	return nil
}
