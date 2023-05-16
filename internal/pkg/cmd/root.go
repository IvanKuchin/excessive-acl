package cmd

import (
	"github.com/spf13/cobra"
)

var Sh_run string
var Sh_route string
var Syslog string
var Go_routines int16

var rootCmd = &cobra.Command{
	Use:   "excessive-acl",
	Short: "excessive-acl is a tool determining excessive ACE",
	Long:  "excessive-acl is a tool determining excessive ACE based on syslog messages from Cisco ASA",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.Flags().StringVarP(&Sh_run, "sh-run", "r", "", "file with \"show run\" output")
	rootCmd.MarkFlagRequired("sh-run")

	rootCmd.Flags().StringVarP(&Syslog, "syslog", "s", "", "syslog file")
	rootCmd.MarkFlagRequired("syslog")

	rootCmd.Flags().StringVarP(&Sh_route, "sh-ip-route", "i", "", "file with \"show ip route\" output")
	rootCmd.MarkFlagRequired("sh-ip-route")

	rootCmd.Flags().Int16VarP(&Go_routines, "go-routines", "g", 1, "number of go routines to process syslog messages")
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}
