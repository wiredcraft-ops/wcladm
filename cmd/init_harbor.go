package cmd

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"text/template"

	homedir "github.com/mitchellh/go-homedir"
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
	dest string
)

var (
	harborConfig = &types.HarborConfiguration{
		HostName:      "registry.wiredcraft.cn",
		Scheme:        "https",
		SSLCert:       "/tmp/certs",
		SSLCertKey:    "/tmp/certs",
		AdminPassword: "12345",
		DBPassword:    "12345",
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

		dir, err := homedir.Expand(dest)
		if err != nil {
			fmt.Println("Cannot get your harbor dest dir")
			os.Exit(1)
		}

		harborTemplates := getTemplates(dir)

		fmt.Println("Rendering harbor templates...")
		writeTemplateFile(harborTemplates)

		fmt.Println("Generating the configuration...")

		var pstdout, pstderr bytes.Buffer
		prepare := exec.Command("python", path.Join(dir, "prepare"))
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
		compose := exec.Command("docker-compose", "-f", path.Join(dir, "docker-compose.yml"), "up", "-d")
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
	harborCmd.Flags().StringVarP(&dest, "dest", "d", "~/.wcladm/harbor", "harbor dest")
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

func getTemplates(dir string) []harborTemplate {

	h := []harborTemplate{
		{"harbor.cfg", templates.HarborConfigTempl, harborConfig},
		{"prepare", templates.HarborPrepareTempl, nil},
		{"docker-compose.yml", templates.HarborDockerComposeTempl, nil},
		{"common/templates/adminserver/env", templates.HarborAdminServerEnvTempl, nil},
		{"common/templates/db/env", templates.HarborDBEnvTempl, nil},
		{"common/templates/nginx/nginx.https.conf", templates.HarborNginxConfigTempl, nil},
		{"common/templates/jobservice/config.yml", templates.HarborJobServerConfigTempl, nil},
		{"common/templates/jobservice/env", templates.HarborJobServerEnvTempl, nil},
		{"common/templates/log/logrotate.conf", templates.HarborLogrotateConfigTempl, nil},
		{"common/templates/registry/config.yml", templates.HarborRegistryConfigTempl, nil},
		{"common/templates/ui/app.conf", templates.HarborUIAppTempl, nil},
		{"common/templates/ui/env", templates.HarborUIEnvTempl, nil},
	}
	for i := range h {
		h[i].Path = path.Join(dir, h[i].Path)
	}
	return h
}
