package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

// resetHarborCmd represents the harbor command
var resetHarborCmd = &cobra.Command{
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

		fmt.Println("Reset harbor...")
		var stdout, stderr bytes.Buffer
		compose := exec.Command("docker-compose", "-f", path.Join(dir, "docker-compose.yml"), "down")
		compose.Stdout = &stdout
		compose.Stderr = &stderr
		if err := compose.Run(); err != nil {
			fmt.Println(stdout.String())
			fmt.Println(stderr.String())
			fmt.Println("Stop harbor failed")
			os.Exit(1)
		}
	},
}

func init() {
	resetCmd.AddCommand(resetHarborCmd)
	resetHarborCmd.Flags().StringVarP(&dest, "dest", "d", "~/.wcladm/harbor", "harbor dest")
}
