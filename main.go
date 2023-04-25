package main

import (
	"fmt"
	"log"

	cisco_asa_acg "github.com/ivankuchin/excessive-acl/internal/cisco-asa-access-group"
	cisco_asa_acl "github.com/ivankuchin/excessive-acl/internal/cisco-asa-access-list"
	"github.com/ivankuchin/excessive-acl/internal/cmd"
)

func main() {
	cmd.Execute()
	in_file := cmd.Sh_run

	// --- parse access-groups in "sh run"
	access_groups, err := cisco_asa_acg.Parse(in_file)
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

	// --- parse access-lists in "sh run"
	access_lists, err := cisco_asa_acl.Parse(in_file, access_groups)
	if err != nil {
		log.Fatal(err)
	}

	if len(access_lists) == 0 {
		log.Println("ERROR: no access-lists found")
		return
	}
	fmt.Println("--- Access-lists")
	for _, acl := range access_lists {
		acl.Print()
	}

}
