package main

// DNS Trace, a tool to trace the DNS path for a given domain. (@nma-io)
// I built this tool to help troubleshoot an issue with an internal dns server.
// Hopefully you find it useful.
// This tool is licensed under the MIT License.
// NO WARRANTY EXPRESSED OR IMPLIED. USE AT YOUR OWN RISK.

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns" // External tool for DNS queries
)

var version = "0.1.0"

func queryRootServerForTLD(tld string, rootServer string) ([]string, error) {
	// Query the nameserver roots for the TLD information.
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(tld), dns.TypeNS)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, rootServer+":53")
	if err != nil {
		return nil, err
	}
	var ns []string

	// Check the Authority section for the referral NS records
	for _, ans := range in.Ns {
		if rr, ok := ans.(*dns.NS); ok {
			ns = append(ns, rr.Ns)
		}
	}
	return ns, nil
}

func queryTLDServerForAuthoritativeNS(domain string, tldServer string) ([]string, error) {
	// Query the TLD nameserver for the authoritative nameserver information.
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, tldServer+":53")
	if err != nil {
		return nil, err
	}

	var ns []string
	// Check the Authority section for NS records
	for _, ans := range in.Ns {
		if rr, ok := ans.(*dns.NS); ok {
			ns = append(ns, rr.Ns)
		}
	}

	return ns, nil
}
func queryNameservers(domain string, nameserver string) ([]string, error) {
	// Construct the DNS query
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)

	// Send the query
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}

	// Extract NS records from the response
	var ns []string
	for _, ans := range in.Answer {
		if rr, ok := ans.(*dns.NS); ok {
			ns = append(ns, rr.Ns)
		}
	}

	// Additionally check the Authority section
	for _, auth := range in.Ns {
		if rr, ok := auth.(*dns.NS); ok {
			ns = append(ns, rr.Ns)
		}
	}

	return ns, nil
}

func resolveDomain(domain string) {
	// Finally, at the end we'll resolve the DNS records for the domain.
	cnames, err := net.LookupCNAME(domain)
	if err != nil {
		fmt.Printf("\tError resolving CNAME for %s: %s\n", domain, err)
		return
	}
	fmt.Printf("\tCNAME for %s: %s\n", domain, cnames)

	ips, err := net.LookupIP(domain)
	if err != nil {
		fmt.Printf("\tError resolving IPs for %s: %s\n", domain, err)
		return
	}

	for _, ip := range ips {
		fmt.Printf("\tIP for %s: %s\n", domain, ip.String())
	}
}

func traceDNSPath(domain string, customNS string) {
	// Our main trace functionality.
	var rootNameservers []string // Change to a slice of strings
	var err error

	if customNS != "" {
		// Use the custom nameserver to query root nameservers
		rootNameservers, err = queryNameservers(".", customNS)
	} else {
		// Use system's default resolver to query root nameservers
		var ns []*net.NS
		ns, err = net.LookupNS(".")
		for _, n := range ns {
			rootNameservers = append(rootNameservers, n.Host)
		}
	}
	if err != nil {
		fmt.Println("Error querying root nameservers:", err)
		return
	}

	fmt.Println("Root Nameservers:")
	for _, ns := range rootNameservers {
		fmt.Println("\t" + ns) // ns is a string, use it directly
	}

	tld := domain[strings.LastIndex(domain, ".")+1:]
	var tldNameservers []string

	// Directly querying a root server for the TLD nameservers
	if len(rootNameservers) > 0 {
		tldNameservers, err = queryRootServerForTLD(tld, rootNameservers[0]) // Use the string directly
		if err != nil {
			fmt.Println("Error querying TLD nameservers from root:", err)
			return
		}
	}

	if len(tldNameservers) == 0 {
		fmt.Printf("No TLD Nameservers found for %s\n", tld)
		return
	}
	fmt.Printf("TLD Nameservers for %s: \n\t%s\n", tld, strings.Join(tldNameservers, "\n\t")) // use \t to indent

	authNameservers := make([]string, 0)
	for _, tldNS := range tldNameservers {
		var authNs []string
		authNs, err = queryTLDServerForAuthoritativeNS(domain, tldNS)
		if err != nil {
			fmt.Printf("Error querying authoritative nameservers from TLD server %s: %s\n", tldNS, err)
			continue
		}
		authNameservers = append(authNameservers, authNs...)
	}

	if len(authNameservers) == 0 {
		fmt.Printf("No Authoritative Nameservers found for %s\n", domain)
		return
	}
	fmt.Printf("Authoritative Nameservers for %s: \n\t%s\n", domain, strings.Join(authNameservers, "\n\t"))
	fmt.Println("Resolving domain...")
	resolveDomain(domain)
	return
}

func main() {
	var customNS string
    fmt.Println("DNS Trace v" + version + " (@nma-io)")
	flag.StringVar(&customNS, "ns", "", "Custom nameserver IP (optional)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "  %s [domain] [flags]\n", os.Args[0])
		fmt.Println("Flags:")
		flag.PrintDefaults()
	}

	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		flag.Usage()
		fmt.Println("No domain provided.\nUsage: dnstrace [domain] [-ns nameserver]")
		return
	}
	domain := args[0]

	fmt.Printf("Tracing DNS path for domain: %s\n", domain)
	if customNS != "" {
		fmt.Printf("Using custom nameserver: %s\n", customNS)
	}
	traceDNSPath(domain, customNS)
}
