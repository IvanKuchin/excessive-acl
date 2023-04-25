package cmd

import (
	"github.com/spf13/cobra"
)

var Sh_run string
var Syslog string

var rootCmd = &cobra.Command{
	Use:   "excessive-acl",
	Short: "excessive-acl is a tool determining excessive ACE",
	Long:  "excessive-acl is a tool determining excessive ACE based on syslog messages from Cisco ASA",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func init() {
	rootCmd.Flags().StringVarP(&Sh_run, "sh-run", "r", "", "sh run file")
	rootCmd.MarkFlagRequired("sh-run")

	rootCmd.Flags().StringVarP(&Syslog, "syslog", "s", "", "syslog file")
	rootCmd.MarkFlagRequired("syslog")
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}
