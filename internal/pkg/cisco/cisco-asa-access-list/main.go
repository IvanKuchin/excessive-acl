package ciscoasaaccesslist

import (
	"fmt"
	"log"

	cisco_asa_access_group "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-group"
	cisco_asa_access_entry "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list/cisco-asa-access-entry"
	sh_run_pipe "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list/sh-run-pipe"
	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
)

func compileACL(acl_name string) (Accesslist, error) {
	var acl Accesslist
	acl.Name = acl_name

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

func (a *Accesslist) AddFlow(flow network_entities.Flow) error {
	for i := range a.aces {
		flow_added, err := a.aces[i].AddFlow(flow)
		if err != nil {
			return err
		}
		if flow_added {
			return nil
		}
	}

	return nil
}

func (a *Accesslist) Analyze() error {
	fmt.Println("ACL:", a.Name)
	for i := range a.aces {
		err := a.aces[i].Analyze()
		if err != nil {
			return err
		}
	}

	return nil
}

func (a Accesslist) Print() {
	fmt.Printf("ACL %s\n", a.Name)

	for _, ace := range a.aces {
		ace.Print()
	}
}
