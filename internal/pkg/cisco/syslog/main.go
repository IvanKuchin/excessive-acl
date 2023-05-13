package syslog

import (
	"bufio"
	"fmt"
	"os"

	app_context "github.com/ivankuchin/excessive-acl/internal/pkg/cisco/app-context"
)

func load(app_ctx app_context.AppContext, in_file string) error {
	readFile, err := os.Open(in_file)
	if err != nil {
		fmt.Println("ERROR:", err)
		return err
	}

	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)

	go func() {
		defer close(app_ctx.Flows)
		defer readFile.Close()

		for fileScanner.Scan() {
			record := fileScanner.Text()

			flow, err := parseRecord(record, app_ctx)
			if err != nil {
				return
			}
			if flow.Protocol == nil {
				continue
			}

			app_ctx.Flows <- flow
		}
	}()

	return nil
}

func Fit(app_ctx app_context.AppContext, in_file string) error {
	err := load(app_ctx, in_file)
	if err != nil {
		return err
	}

	return nil
}
