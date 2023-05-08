package ciscoasaaccessentry

import (
	"fmt"

	"github.com/ivankuchin/excessive-acl/internal/pkg/network_entities"
)

func (a *AccessEntry) AddFlow(flow network_entities.Flow) (bool, error) {
	for i := range a.compiled {
		is_match, err := a.compiled[i].MatchFlow(flow)
		if err != nil {
			return false, err
		}

		fmt.Printf("\tis_match: %v\n\t\t%s\n\t\t%s\n", is_match, a.compiled[i], flow)

		if is_match {
			err = a.compiled[i].AddFlow(flow)
			if err != nil {
				return false, err
			}
			return true, nil
		}
	}

	return false, nil
}
