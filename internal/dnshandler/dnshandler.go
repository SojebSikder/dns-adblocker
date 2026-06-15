package dnshandler

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

const (
	upstreamDNS = "1.1.1.1:53"
	listenAddr  = ":53"
	// management server address
	mgmtAddr    = ":8080"
	blacklistFn = "data/blacklist.txt"
)

type DNSHandler struct {
	mu        sync.RWMutex
	blacklist map[string]bool
	Client    *dns.Client
}

// loadBlacklist reads domains from the file and stores them in memory
func (h *DNSHandler) LoadBlacklist() {
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

		domain := strings.ToLower(line)
		if !strings.HasSuffix(domain, ".") {
			domain += "."
		}
		h.blacklist[domain] = true
	}
	log.Printf("[MEM] Loaded %d blocked domains into memory.", len(h.blacklist))
}

// isBlocked checks if a domain or any of its parent domains are blacklisted
func (h *DNSHandler) isBlocked(qName string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// check exact match (e.g. doubleclick.net.)
	if h.blacklist[qName] {
		return true
	}

	// check parent domains (e.g. video.ads.doubleclick.net.)
	labels := dns.SplitDomainName(qName)
	for i := 1; i < len(labels); i++ {
		parent := strings.Join(labels[i:], ".") + "."
		if h.blacklist[parent] {
			return true
		}
	}

	return false
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		w.WriteMsg(msg)
		return
	}

	question := r.Question[0]
	qName := strings.ToLower(question.Name)

	// wildcard/subdomain matching
	if h.isBlocked(qName) {
		if question.Qtype == dns.TypeA {
			log.Printf("BLOCKED (IPv4): %s", qName)
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A 0.0.0.0", qName))
			if err == nil {
				msg.Answer = append(msg.Answer, rr)
			}
			w.WriteMsg(msg)
			return
		}

		if question.Qtype == dns.TypeAAAA {
			log.Printf("BLOCKED (IPv6): %s", qName)
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA ::", qName))
			if err == nil {
				msg.Answer = append(msg.Answer, rr)
			}
			w.WriteMsg(msg)
			return
		}
	}

	// If not blocked, forward to upstream DNS using the shared client
	log.Printf("ALLOWED: %s (Type %d)", qName, question.Qtype)
	response, _, err := h.Client.Exchange(r, upstreamDNS)
	if err != nil {
		log.Printf("Upstream error for %s: %v", qName, err)
		dns.HandleFailed(w, r)
		return
	}

	w.WriteMsg(response)
}
