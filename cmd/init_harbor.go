package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"text/template"

	"github.com/howeyc/gopass"
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

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

var (
	dest          string
	hostname      string
	scheme        string
	sslCert       string
	sslCertKey    string
	adminPassword string
	dbPassword    string
	dev           bool
)

// initHarborCmd represents the harbor command
var initHarborCmd = &cobra.Command{
	Use:   "harbor",
	Short: "Init an Harbor",
	Long:  `Generate configuration files for habror and start it by docker`,
	Run: func(cmd *cobra.Command, args []string) {

		dir, err := homedir.Expand(dest)
		if err != nil {
			fmt.Println("Cannot get your harbor dest dir")
			os.Exit(1)
		}

		if dev {
			scheme = "http"
			adminPassword = "12345"
			dbPassword = "12345"
		}

		if scheme == "https" {
			if sslCert == "" {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("SSL Cert file (.crt): ")
				if sslCert, err = reader.ReadString('\n'); err != nil {
					fmt.Println(err)
					return
				}
			}

			if sslCertKey == "" {
				reader := bufio.NewReader(os.Stdin)
				fmt.Print("SSL CertKey file (.key): ")
				if sslCertKey, err = reader.ReadString('\n'); err != nil {
					fmt.Println(err)
					return
				}
			}

			//TODO: Make sure sslCert and sslCertKey file exist
		}

		if adminPassword == "" {
			fmt.Printf("Admin Password: ")
			pass, err := gopass.GetPasswdMasked()
			if err != nil {
				fmt.Println(err)
				return
			}
			adminPassword = string(pass)
			if adminPassword == "" {
				adminPassword = randStringBytes(10)
			}
		}

		if dbPassword == "" {
			fmt.Printf("DB Password: ")
			pass, err := gopass.GetPasswdMasked()
			if err != nil {
				fmt.Println(err)
				return
			}
			dbPassword = string(pass)
			if dbPassword == "" {
				dbPassword = randStringBytes(10)
			}
		}

		harborConfig := &types.HarborConfiguration{
			HostName:      hostname,
			Scheme:        scheme,
			SSLCert:       sslCert,
			SSLCertKey:    sslCertKey,
			AdminPassword: adminPassword,
			DBPassword:    dbPassword,
		}

		harborTemplates := []harborTemplate{
			{"harbor.cfg", templates.HarborConfigTempl, harborConfig},
			{"prepare", templates.HarborPrepareTempl, nil},
			{"docker-compose.yml", templates.HarborDockerComposeTempl, nil},
			{"common/templates/adminserver/env", templates.HarborAdminServerEnvTempl, nil},
			{"common/templates/db/env", templates.HarborDBEnvTempl, nil},
			{"common/templates/nginx/nginx.https.conf", templates.HarborNginxHTTPSConfigTempl, nil},
			{"common/templates/nginx/nginx.http.conf", templates.HarborNginxHTTPConfigTempl, nil},
			{"common/templates/jobservice/config.yml", templates.HarborJobServerConfigTempl, nil},
			{"common/templates/jobservice/env", templates.HarborJobServerEnvTempl, nil},
			{"common/templates/log/logrotate.conf", templates.HarborLogrotateConfigTempl, nil},
			{"common/templates/registry/config.yml", templates.HarborRegistryConfigTempl, nil},
			{"common/templates/ui/app.conf", templates.HarborUIAppTempl, nil},
			{"common/templates/ui/env", templates.HarborUIEnvTempl, nil},
		}
		for i := range harborTemplates {
			harborTemplates[i].Path = path.Join(dir, harborTemplates[i].Path)
		}

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

		fmt.Println("\n\n\nStarted:")
		fmt.Printf("%s://%s\n", scheme, hostname)
		fmt.Printf("Admin password: %s\n", adminPassword)
		fmt.Printf("DB password: %s\n", dbPassword)
	},
}

func init() {
	initCmd.AddCommand(initHarborCmd)
	initHarborCmd.Flags().StringVarP(&dest, "dest", "d", "~/.wcladm/harbor", "harbor dest")
	initHarborCmd.Flags().StringVar(&hostname, "hostname", "registry.wiredcraft.cn", "hostname for harbor")
	initHarborCmd.Flags().StringVar(&scheme, "scheme", "https", "scheme for harbor, 'https' or 'http'")
	initHarborCmd.Flags().StringVar(&sslCert, "ssl-cert", "", "ssl cert file path, required when 'scheme' is 'https'")
	initHarborCmd.Flags().StringVar(&sslCertKey, "ssl-key", "", "ssl cert key file path, required when 'scheme' is 'https'")
	initHarborCmd.Flags().StringVar(&adminPassword, "admin-pass", "", "harbor admin password")
	initHarborCmd.Flags().StringVar(&dbPassword, "db-pass", "", "harbor db password")
	initHarborCmd.Flags().BoolVar(&dev, "dev", false, "init an harbor for dev mode(simple pass & http)")
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

func randStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
