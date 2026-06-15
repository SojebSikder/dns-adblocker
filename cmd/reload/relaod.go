package reload

import (
	"github.com/sojebsikder/dns-adblocker/cmd/server"
	"github.com/spf13/cobra"
)

var ReloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload the blacklist",
	Run: func(cmd *cobra.Command, args []string) {
		reloadBlacklist()
	},
}

func reloadBlacklist() {
	server.Handler.LoadBlacklist()
}
