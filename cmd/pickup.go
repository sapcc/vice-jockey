package cmd

import (
	"fmt"

	"github.com/sapcc/vice-jockey/pkg/jockey"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(pickupCmd)
}

var pickupCmd = &cobra.Command{
	Use:   "pickup",
	Short: "Picks up an approved certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("You need to provide a config file")
		}

		if err := validateFlags(); err != nil {
			return err
		}
		return jockey.Pickup(args[0])
	},
}
