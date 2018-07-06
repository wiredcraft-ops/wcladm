package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var (
	pipelinesGHOAuthKey    string
	pipelinesGHOAuthSecret string
	pipelinesGHOAuthTeam   string
	pipelinesUsername      string
	pipelinesPassword      string
	pipelinesDev           bool
)

// initPipelinesCmd represents the initpipelines command
var initPipelinesCmd = &cobra.Command{
	Use:   "pipelines",
	Short: "Init a pipelines server",
	Long:  `Use docker to run a pipelines server`,
	Run: func(cmd *cobra.Command, args []string) {
		if pipelinesDev {
			pipelinesUsername = "admin"
			pipelinesPassword = "admin"
		}

		if pipelinesUsername != "" && pipelinesPassword != "" {
			var stdout, stderr bytes.Buffer
			command := fmt.Sprintf(`docker run -d \
										--name wcladmin-pipelines \
										-p 8888 \
										-e ADMIN_USER=%s \
										-e ADMIN_PASS=%s \
										boratbot/pipelines`, pipelinesUsername, pipelinesPassword)
			prepare := exec.Command("sh", "-c", command)
			prepare.Stdout = &stdout
			prepare.Stderr = &stderr
			if err := prepare.Run(); err != nil {
				fmt.Println(stdout.String())
				fmt.Println(stderr.String())
				fmt.Println(err)
				fmt.Println("Start Pipelines failed")
				os.Exit(1)
			}
			return
		}

		if pipelinesGHOAuthSecret != "" && pipelinesGHOAuthKey != "" && pipelinesGHOAuthTeam != "" {
			var stdout, stderr bytes.Buffer
			command := fmt.Sprintf(`docker run -d \
										--name wcladmin-pipelines \
										-p 8888 -e GH_OAUTH_KEY=%s \
										-e GH_OAUTH_SECRET=%s \
										boratbot/pipelines \
										pipelines server \
											--github-auth=%s \
											--host 0.0.0.0`,
				pipelinesGHOAuthKey, pipelinesGHOAuthSecret, pipelinesGHOAuthTeam)
			prepare := exec.Command("sh", "-c", command)
			prepare.Stdout = &stdout
			prepare.Stderr = &stderr
			if err := prepare.Run(); err != nil {
				fmt.Println(stdout.String())
				fmt.Println(stderr.String())
				fmt.Println(err)
				fmt.Println("Start Pipelines failed")
				os.Exit(1)
			}
		}
	},
}

func init() {
	initCmd.AddCommand(initPipelinesCmd)
	initPipelinesCmd.Flags().StringVar(&pipelinesGHOAuthKey, "gh-oauth-key", "", "Github OAuth key")
	initPipelinesCmd.Flags().StringVar(&pipelinesGHOAuthSecret, "gh-oauth-secret", "", "Github OAuth Secret")
	initPipelinesCmd.Flags().StringVar(&pipelinesGHOAuthTeam, "gh-oauth-team", "Wiredcraft/core-members,Wiredcraft/leaders", "Github OAuth Team")
	initPipelinesCmd.Flags().StringVar(&pipelinesUsername, "username", "", "amdin username")
	initPipelinesCmd.Flags().StringVar(&pipelinesPassword, "password", "", "admin password")
	initPipelinesCmd.Flags().BoolVar(&pipelinesDev, "dev", true, "init pipelines for dev mode(simple pass)")
}
