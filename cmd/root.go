package cmd

import (
	"flag"
	"fmt"

	"github.com/sapcc/vice-jockey/pkg/jockey"
	"github.com/spf13/cobra"
)

var RootCmd = &cobra.Command{
	Use: "vice-jockey",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return validateFlags()
	},
}

func InitFlags() {
	flag.Parse()
	flag.Set("logtostderr", "true")

	RootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
	RootCmd.PersistentFlags().StringVar(&jockey.CertFile, "cert", "", "Path to the PEM encoded certificate used for authentication")
	RootCmd.PersistentFlags().StringVar(&jockey.KeyFile, "key", "", "Path to the PEM encoded private key used for authentication")
	RootCmd.PersistentFlags().StringVar(&jockey.Workdir, "work_dir", "", "Path to the PEM encoded private key used for authentication")
}

func validateFlags() error {
	if jockey.CertFile == "" {
		return fmt.Errorf("You need to provide a cert file")
	}

	if jockey.KeyFile == "" {
		return fmt.Errorf("You need to provide a key file")
	}

	return nil
}
