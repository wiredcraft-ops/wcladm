package cmd

import (
	"log"
	"os"
	"path/filepath"
	"text/template"

	"github.com/spf13/cobra"
	"github.com/wiredcraft-ops/wcladm/templates"
	"github.com/wiredcraft-ops/wcladm/types"
)

type harborTemplate struct {
	Path     string
	Template *template.Template
	Data     interface{}
}

var (
	harborConfig = &types.HarborConfiguration{
		HostName:      "registry.wiredcraft.cn",
		Scheme:        "https",
		SSLCert:       "/tmp/certs",
		SSLCertKey:    "/tmp/certs",
		AdminPassword: "12345",
		DBPassword:    "12345",
	}

	harborTemplates = []harborTemplate{
		{"common/templates/nginx/nginx.conf", templates.HarborNginxConfigTempl, nil},
	}
)

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

func writeTemplateFile(ts []harborTemplate) {
	for _, t := range ts {
		dir, _ := filepath.Split(t.Path)
		if err := mkdir(dir); err != nil {
			return
		}

		f, err := os.Create(t.Path)
		if err != nil {
			log.Println("create file: ", err)
			return
		}

		err = t.Template.Execute(f, t.Data)
		if err != nil {
			log.Print("execute: ", err)
			return
		}
		f.Close()
	}
}

func mkdir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
	}
	return nil
}
