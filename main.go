package main

import (
	"os"

	"github.com/sapcc/vice-jockey/cmd"
)

func main() {
	cmd.InitFlags()

	if err := cmd.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
