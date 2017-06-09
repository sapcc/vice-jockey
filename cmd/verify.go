package cmd

import (
	"fmt"

	"github.com/sapcc/vice-jockey/pkg/jockey"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(verifyCmd)
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verifies a certificate against its CN",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("You need to provide a config file")
		}

		if err := validateFlags(); err != nil {
			return err
		}
		return jockey.Validate(args[0])
	},
}
