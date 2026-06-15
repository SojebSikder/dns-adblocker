package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	upstreamDNS = "1.1.1.1:53"
	listenAddr  = ":53"
	blacklistFn = "data/blacklist.txt"
)

type DNSHandler struct {
	mu        sync.RWMutex
	blacklist map[string]bool
}

// loadBlacklist reads domains from the file and stores them in memory
func (h *DNSHandler) loadBlacklist() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.blacklist = make(map[string]bool)
	file, err := os.Open(blacklistFn)
	if err != nil {
		log.Printf("%s not found. Starting with empty blacklist.", blacklistFn)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// DNS names always end with a dot internally (e.g., "google.com.")
		domain := strings.ToLower(line)
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}
		h.blacklist[domain] = true
	}
	log.Printf("Loaded %d blocked domains into memory.", len(h.blacklist))
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	// Ensure there is at least one question in the DNS packet
	if len(r.Question) == 0 {
		w.WriteMsg(msg)
		return
	}

	question := r.Question[0]
	qName := strings.ToLower(question.Name)

	h.mu.RLock()
	isBlocked := h.blacklist[qName]
	h.mu.RUnlock()

	// Block standard IPv4 (A) requests if they match the blacklist
	if isBlocked {
		if question.Qtype == dns.TypeA {
			log.Printf("BLOCKED: %s", qName)

			// Spoof response with 0.0.0.0
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A 0.0.0.0", qName))
			if err == nil {
				msg.Answer = append(msg.Answer, rr)
			}
		} else if question.Qtype == dns.TypeAAAA {
			log.Printf("BLOCKED: %s", qName)

			// Spoof response with ::
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA ::", qName))
			if err == nil {
				msg.Answer = append(msg.Answer, rr)
			}
		}
		w.WriteMsg(msg)
		return
	}

	// If not blocked, forward to upstream DNS
	log.Printf("ALLOWED: %s", qName)
	client := &dns.Client{Timeout: 2 * time.Second}
	response, _, err := client.Exchange(r, upstreamDNS)
	if err != nil {
		log.Printf("Upstream error for %s: %v", qName, err)
		dns.HandleFailed(w, r)
		return
	}

	// Send the upstream response back to the client
	w.WriteMsg(response)
}

func main() {
	handler := &DNSHandler{}
	handler.loadBlacklist()

	server := &dns.Server{
		Addr:    listenAddr,
		Net:     "udp",
		Handler: handler,
	}

	log.Printf("Go DNS Ad Blocker listening on %s...", listenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %s\nNote: You might need sudo/administrator privileges to bind to port 53.", err)
	}
}
