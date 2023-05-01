package ciscoasaaccesslist

import (
	"errors"

	cisco_asa_access_entry "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/cisco-asa-access-list/cisco-asa-access-entry"
)

type Accesslist struct {
	name string
	aces []cisco_asa_access_entry.AccessEntry
}

var ErrorACLNotFound = errors.New("ACL not found")
