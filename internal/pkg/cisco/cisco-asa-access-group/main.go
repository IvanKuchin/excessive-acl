package ciscoasaaccessgroup

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func isAccessGroup(str string) (*Accessgroup, error) {
	const prefix = "access-group "
	if len(str) > len(prefix) {
		if str[:len(prefix)] == prefix {
			fields := strings.Fields(str)
			if len(fields) == 5 {
				var direction direction
				if fields[2] == "in" {
					direction = Inbound
				} else {
					direction = Outbound
				}

				return &Accessgroup{Iface: fields[4], Acl_name: fields[1], Direction: direction}, nil
			}
		}
	}
	return nil, nil
}

func Parse(in_file string) ([]Accessgroup, error) {
	var ags []Accessgroup

	readFile, err := os.Open(in_file)
	if err != nil {
		// log.Println(err)
		return nil, err
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		ag, err := isAccessGroup(fileScanner.Text())
		if err != nil {
			// log.Println(err)
			return nil, err
		}

		if ag != nil {
			ags = append(ags, *ag)
		}
	}

	return ags, nil
}

func (acg Accessgroup) Print() {
	fmt.Printf("access-group %v\n", acg)
}
