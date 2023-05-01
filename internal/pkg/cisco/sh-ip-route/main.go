package sh_ip_route

import (
	"bufio"
	"log"
	"os"
	"strings"
)

func init() {
	ifaces = make(map[string]string)
}

func readFile(in_file string) ([]string, error) {
	readFile, err := os.Open(in_file)
	if err != nil {
		log.Println("ERROR:", err)
		return nil, err
	}
	defer readFile.Close()

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	var f_content []string
	for fileScanner.Scan() {
		f_content = append(f_content, fileScanner.Text())
	}

	return f_content, nil
}

func cutoffHeader(f_content []string) []string {
	var i int
	for _, line := range f_content {
		if strings.HasPrefix(line, "Gateway of last resort") {
			return f_content[i+1:]
		}
		i++
	}
	return f_content
}

func Fit(fname string) (RoutingTable, error) {
	var routing_table RoutingTable

	f_content, err := readFile(fname)
	if err != nil {
		return routing_table, err
	}
	f_content = cutoffHeader(f_content)

	ifaces, err = findAllIfaceNames()
	if err != nil {
		return routing_table, err
	}

	routing_table, err = parseRoutingTable(f_content)
	if err != nil {
		return routing_table, err
	}

	return routing_table, nil
}
