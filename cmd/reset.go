package cmd

import (
	"github.com/spf13/cobra"
)

// resetCmd represents the reset command
var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset components",
	Long:  `Undo the changes you made with wcladm`,
}

func init() {
	rootCmd.AddCommand(resetCmd)
}
