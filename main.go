package main

import (
	"fmt"
	"log"
	"time"

	acl_match "github.com/ivankuchin/excessive-acl/internal/pkg/acl_match"
	app_context "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/app-context"
	cisco_asa_acg "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-group"
	cisco_asa_acl "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list"
	sh_ip_route "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/sh-ip-route"
	"github.com/ivankuchin/excessive-acl/internal/pkg/cisco/syslog"
	"github.com/ivankuchin/excessive-acl/internal/pkg/cmd"
	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
	"github.com/ivankuchin/excessive-acl/internal/pkg/utils"
)

func main() {
	cmd.Execute()
	sh_run, ip_route_file, syslog_file := cmd.Sh_run, cmd.Sh_route, cmd.Syslog
	num_goroutines := cmd.Go_routines

	utils.SetLogLevel(utils.Info)

	// --- parse access-groups in "sh run"
	access_groups, err := cisco_asa_acg.Parse(sh_run)
	if err != nil {
		log.Fatal(err)
	}
	if len(access_groups) == 0 {
		log.Println("no access-group found")
		return
	}

	fmt.Println("--- Access-groups")
	for _, access_group := range access_groups {
		access_group.Print()
	}

	// parse access-lists in "sh run"
	t0 := time.Now()
	access_lists, err := cisco_asa_acl.Parse(sh_run, access_groups)
	if err != nil {
		log.Fatal(err)
	}
	t1 := time.Since(t0)

	if len(access_lists) == 0 {
		log.Println("ERROR: no access-lists found")
		return
	}

	fmt.Printf("--- Access-lists\n")
	if utils.GetLogLevel() == utils.Trace {
		for _, acl := range access_lists {
			acl.Print()
		}
	}
	fmt.Printf("=== Access-lists (%v sec)\n", t1.Seconds())

	fmt.Printf("--- Routing table\n")
	routing_table, err := sh_ip_route.Fit(ip_route_file)
	if err != nil {
		log.Fatal(err)
	}

	if utils.GetLogLevel() == utils.Trace {
		routing_table.PrintTree()
	}
	fmt.Printf("=== Routing table\n")

	fmt.Printf("--- Syslog parsing \n")

	app_ctx := app_context.AppContext{
		Access_groups: access_groups,
		Access_lists:  access_lists,
		Routing_table: routing_table,
	}
	app_ctx.Flows = make(chan network_entities.Flow, 100)

	t0 = time.Now()
	err = syslog.Fit(app_ctx, syslog_file)
	if err != nil {
		log.Fatal(err)
	}

	err = acl_match.StartRoutines(int(num_goroutines), app_ctx)
	if err != nil {
		log.Fatal(err)
	}
	t1 = time.Since(t0)
	fmt.Printf("=== Syslog parsing (%v sec)\n", t1.Seconds())

	t0 = time.Now()
	fmt.Println("--- Analysis")
	for _, acl := range access_lists {
		err := acl.Analyze()
		if err != nil {
			log.Fatal(err)
		}
	}
	t1 = time.Since(t0)
	fmt.Printf("=== Analysis (%v sec)\n", t1.Seconds())
}
