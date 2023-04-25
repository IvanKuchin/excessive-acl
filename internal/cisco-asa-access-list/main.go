package ciscoasaaccesslist

import (
	"fmt"
	"log"

	cisco_asa_access_group "github.com/ivankuchin/excessive-acl/internal/cisco-asa-access-group"
	cisco_asa_access_entry "github.com/ivankuchin/excessive-acl/internal/cisco-asa-access-list/cisco-asa-access-entry"
	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/cisco-asa-access-list/sh-run-pipe"
)

func compileACL(acl_name string) (Accesslist, error) {
	var acl Accesslist
	acl.name = acl_name

	acl_text := sh_run_pipe.Prefix("access-list " + acl_name)

	if len(acl_text) == 0 {
		err := ErrorACLNotFound
		log.Printf("ERROR: %s %s", err, acl_name)
		return acl, err
	}

	for _, ace_text := range acl_text {
		_ace, err := cisco_asa_access_entry.Parse(ace_text)
		if err != nil {
			return acl, err
		}
		acl.aces = append(acl.aces, _ace)
	}

	return acl, nil
}

func Parse(in_file string, access_groups []cisco_asa_access_group.Accessgroup) ([]Accesslist, error) {
	err := sh_run_pipe.Load(in_file)
	if err != nil {
		return nil, err
	}

	var acls []Accesslist

	for _, access_group := range access_groups {
		acl, err := compileACL(access_group.Acl_name)
		if err != nil {
			return nil, err
		}

		acls = append(acls, acl)
	}

	return acls, nil
}

func (a Accesslist) Print() {
	fmt.Printf("ACL %s\n", a.name)

	for _, ace := range a.aces {
		ace.Print()
	}
}
