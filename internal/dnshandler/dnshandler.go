package dnshandler

import (
	"bufio"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

const (
	upstreamDNS = "1.1.1.1:53"
	listenAddr  = ":53"
	blacklistFn = "data/blacklist.txt"
)

type DNSHandler struct {
	blacklist atomic.Value // stores map[string]bool
	Client    *dns.Client
}

func NewDNSHandler() *DNSHandler {
	h := &DNSHandler{
		Client: &dns.Client{
			Net:            "udp",
			SingleInflight: true, // Prevents duplicate upstream queries for the same domain
		},
	}
	h.blacklist.Store(make(map[string]bool))
	return h
}

// LoadBlacklist reads domains from the file and atomically swaps the memory pointer
func (h *DNSHandler) LoadBlacklist() {
	file, err := os.Open(blacklistFn)
	if err != nil {
		log.Printf("%s not found. Starting with empty blacklist.", blacklistFn)
		return
	}
	defer file.Close()

	newMap := make(map[string]bool)
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
		newMap[domain] = true
	}

	h.blacklist.Store(newMap)
}

// isBlocked checks if a domain or any of its parent domains are blacklisted
func (h *DNSHandler) isBlocked(qName string) bool {
	blacklist := h.blacklist.Load().(map[string]bool)

	// check exact match (e.g. doubleclick.net.)
	if blacklist[qName] {
		return true
	}

	// zero allocation parent scanning (e.g., "video.ads.doubleclick.net.")
	// slice the existing string instead of splitting/joining.
	for i := 0; i < len(qName)-1; i++ {
		if qName[i] == '.' {
			parent := qName[i+1:]
			if blacklist[parent] {
				return true
			}
		}
	}

	return false
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		msg := new(dns.Msg)
		msg.SetReply(r)
		w.WriteMsg(msg)
		return
	}

	question := r.Question[0]
	qName := strings.ToLower(question.Name)

	// handle reverse DNS lookup (PTR records)
	if question.Qtype == dns.TypePTR && qName == "1.0.0.127.in-addr.arpa." {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true

		serverName := "sojeb-dns."

		msg.Answer = append(msg.Answer, &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			Ptr: serverName,
		})
		w.WriteMsg(msg)
		return
	}

	if h.isBlocked(qName) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true

		switch question.Qtype {
		case dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4zero, // 0.0.0.0
			})
			w.WriteMsg(msg)
			return

		case dns.TypeAAAA:
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.IPv6zero, // ::
			})
			w.WriteMsg(msg)
			return
		}
	}

	// Forward to upstream
	response, _, err := h.Client.Exchange(r, upstreamDNS)
	if err != nil {
		dns.HandleFailed(w, r)
		return
	}

	w.WriteMsg(response)
}
