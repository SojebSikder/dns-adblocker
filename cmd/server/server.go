package server

import (
	"log"
	"time"

	"github.com/miekg/dns"
	"github.com/sojebsikder/dns-adblocker/internal/dnshandler"
	"github.com/spf13/cobra"
)

const (
	listenAddr = ":53"
	mgmtAddr   = ":8080" // Port for hot-reloading
)

var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the web server",
	Run: func(cmd *cobra.Command, args []string) {
		startServer()
	},
}

var Handler = &dnshandler.DNSHandler{
	Client: &dns.Client{Timeout: 2 * time.Second},
}

func startServer() {
	Handler.LoadBlacklist()

	// Start HTTP Server for Hot-Reloading
	// management.StartManagementServer(mgmtAddr, Handler)

	server := &dns.Server{
		Addr:    listenAddr,
		Net:     "udp",
		Handler: Handler,
	}

	log.Printf("[DNS] DNS AdBlocker listening on %s...", listenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %s\nNote: You might need sudo/administrator privileges to bind to port 53.", err)
	}
}
