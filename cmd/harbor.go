package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/wiredcraft-ops/wcladm/templates"
	"github.com/wiredcraft-ops/wcladm/types"
)

var harborConfig = &types.HarborConfiguration{
	HostName:      "registry.wiredcraft.cn",
	Scheme:        "https",
	SSLCert:       "/tmp/certs",
	SSLCertKey:    "/tmp/certs",
	AdminPassword: "12345",
	DBPassword:    "12345",
}

// harborCmd represents the harbor command
var harborCmd = &cobra.Command{
	Use:   "harbor",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		/* err := harborConfigTempl.Execute(os.Stdout, harborConfig)
		if err != nil {
			log.Println("executing template:", err)
		} */
		err := templates.HarborPrepareTempl.Execute(os.Stdout, nil)
		if err != nil {
			log.Println("executing template:", err)
		}
	},
}

func init() {
	initCmd.AddCommand(harborCmd)
}
