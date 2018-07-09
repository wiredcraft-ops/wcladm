package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// resetPipelinesCmd represents the resetPipelines command
var resetPipelinesCmd = &cobra.Command{
	Use:   "pipelines",
	Short: "Reset pipelines",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Reset pipelines...")

		var stdout, stderr bytes.Buffer
		compose := exec.Command("docker", "rm", "-f", "wcladmin-pipelines")
		compose.Stdout = &stdout
		compose.Stderr = &stderr
		if err := compose.Run(); err != nil {
			fmt.Println(stdout.String())
			fmt.Println(stderr.String())
			fmt.Println("Reset pipelines failed")
			os.Exit(1)
		}
	},
}

func init() {
	resetCmd.AddCommand(resetPipelinesCmd)
}
