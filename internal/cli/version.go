package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/thexsa/peep/internal/ui"
	"github.com/thexsa/peep/internal/updater"
)

// Version is set at build time via ldflags.
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of peep",
	Run: func(cmd *cobra.Command, args []string) {
		if showExamples(cmd.Name()) {
			return
		}
		method := updater.DetectInstallMethod(Version)
		platform := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
		fmt.Println(ui.RenderVersion(Version, method.String(), platform))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
