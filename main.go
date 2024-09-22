package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/term"
)

type unifiClient struct {
	client    *http.Client
	csrfToken string
	siteID    string
	endpoint  string
}

func main() {

	var endpoint, username, clientFile, mfatoken, password string
	flag.StringVar(&endpoint, "endpoint", "https://192.168.1.1", "Controller endpoint")
	flag.StringVar(&clientFile, "clientFile", "clients.txt", "path to the file of clients")
	flag.Parse()

	fmt.Printf("Enter your Unifi username: ")
	fmt.Scan(&username)

	fmt.Printf("Enter your Unifi password: ")
	b, err := term.ReadPassword(0)
	if err != nil {
		log.Fatalln(err)
	}
	password = string(b)
	fmt.Println()

	fmt.Printf("Enter the MFA token: ")
	fmt.Scan(&mfatoken)
	fmt.Println()

	unifi, err := newClient(endpoint, username, password, mfatoken)
	if err != nil {
		log.Fatalf("failed to construct unifi client: %v", err)
	}

	err = unifi.getSiteID()
	if err != nil {
		log.Fatalln(err)
	}

	f, err := os.Open(clientFile)
	if err != nil {
		log.Fatalf("failed to open clientFile: %v", err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		if !strings.Contains(s.Text(), "192.168") {
			log.Printf("Skipping line %q - did not see 192.168 in it\n", s.Text())
			continue
		}

		fields := strings.Fields(s.Text())
		numFields := len(fields)
		if numFields <= 2 {
			log.Printf("Skipping line %q - insufficient number of fields (%d) in it\n", s.Text(), numFields)
			continue

		}
		hc := &homeClient{
			Name:                  strings.TrimSpace(fields[0]),
			Mac:                   strings.TrimSpace(fields[1]),
			FixedIP:               strings.TrimSpace(fields[2]),
			UseFixedip:            true,
			LocalDNSRecordEnabled: false,
		}

		if !strings.Contains(hc.Mac, `:`) {
			log.Printf("skipping line %q - appears to be malformed MAC address", s.Text())
			continue
		}

		err = unifi.updateHomeClient(hc)
		if err != nil {
			log.Fatalf("got error configuring client: %v", err)
		}

	}

	if err := s.Err(); err != nil {
		log.Fatalf("got error from scanner: %v", err)
	}

}
