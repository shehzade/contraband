package main

import (
	"fmt"
	"runtime"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display version, build date, target architecture, and CGO status",
	Run: func(cmd *cobra.Command, args []string) {
		out := cmd.OutOrStdout()
		fmt.Fprintf(out, "Contraband Egress Assessment Framework\n")
		fmt.Fprintf(out, "  Version:      %s\n", common.Version)
		fmt.Fprintf(out, "  Commit:       %s\n", common.Commit)
		fmt.Fprintf(out, "  Build Date:   %s\n", common.BuildDate)
		fmt.Fprintf(out, "  Built By:     %s\n", common.BuiltBy)
		fmt.Fprintf(out, "  Go Version:   %s\n", runtime.Version())
		fmt.Fprintf(out, "  OS/Arch:      %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Fprintf(out, "  CGO_ENABLED:  0 (Static pure-Go binary)\n")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
