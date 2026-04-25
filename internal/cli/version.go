package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/ui"
)

// Version is set at build time via ldflags.
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of peep",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(ui.RenderVersion(Version))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
