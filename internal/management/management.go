package management

import (
	"fmt"
	"log"
	"net/http"

	"github.com/sojebsikder/dns-adblocker/internal/dnshandler"
)

func StartManagementServer(addr string, handler *dnshandler.DNSHandler) {
	mux := http.NewServeMux()

	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		handler.LoadBlacklist()
		fmt.Fprintln(w, "Blacklist reloaded successfully!")
		log.Println("[MGMT] Blacklist reloaded via API")
	})

	log.Printf("[MGMT] Admin server listening on http://127.0.0.0.1%s/reload", addr)

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil && err != http.ErrServerClosed {
			log.Printf("[MGMT] Failed to start admin server: %v", err)
		}
	}()
}
