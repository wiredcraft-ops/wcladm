package cmd

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
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
		{"/tmp/wcladm-harbor/common/templates/nginx/nginx.https.conf", templates.HarborNginxConfigTempl, nil},
		{"/tmp/wcladm-harbor/harbor.cfg", templates.HarborConfigTempl, harborConfig},
		{"/tmp/wcladm-harbor/prepare", templates.HarborPrepareTempl, nil},
		{"/tmp/wcladm-harbor/docker-compose.yml", templates.HarborDockerComposeTempl, nil},
		{"/tmp/wcladm-harbor/common/templates/adminserver/env", templates.HarborAdminServerEnvTempl, nil},
		{"/tmp/wcladm-harbor/common/templates/db/env", templates.HarborDBEnvTempl, nil},
		{"/tmp/wcladm-harbor/common/templates/jobservice/config.yml", templates.HarborJobServerConfigTempl, nil},
		{"/tmp/wcladm-harbor/common/templates/jobservice/env", templates.HarborJobServerEnvTempl, nil},
		{"/tmp/wcladm-harbor/common/templates/log/logrotate.conf", templates.HarborLogrotateConfigTempl, nil},
		{"/tmp/wcladm-harbor/common/templates/registry/config.yml", templates.HarborRegistryConfigTempl, nil},
		{"/tmp/wcladm-harbor/common/templates/ui/app.conf", templates.HarborUIAppTempl, nil},
		{"/tmp/wcladm-harbor/common/templates/ui/env", templates.HarborUIEnvTempl, nil},
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
		fmt.Println("Rendering harbor templates...")
		writeTemplateFile(harborTemplates)

		fmt.Println("Generating the configuration...")

		var pstdout, pstderr bytes.Buffer
		prepare := exec.Command("python", "/tmp/wcladm-harbor/prepare")
		prepare.Stdout = &pstdout
		prepare.Stderr = &pstderr
		if err := prepare.Run(); err != nil {
			fmt.Println(pstdout.String())
			fmt.Println(pstderr.String())
			fmt.Println("Generated the configuration failed")
			os.Exit(1)
		}

		fmt.Println("Starting harbor...")
		var cstdout, cstderr bytes.Buffer
		compose := exec.Command("docker-compose", "-f", "/tmp/wcladm-harbor/docker-compose.yml", "up", "-d")
		compose.Stdout = &cstdout
		compose.Stderr = &cstderr
		if err := compose.Run(); err != nil {
			fmt.Println(cstdout.String())
			fmt.Println(cstderr.String())
			fmt.Println("Start harbor failed")
			os.Exit(1)
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
