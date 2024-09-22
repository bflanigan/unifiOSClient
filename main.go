package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/term"
)

func main() {

	var endpoint, username, clientFile, mfatoken, password string
	var initialSetup bool
	flag.StringVar(&endpoint, "endpoint", "https://192.168.1.1", "Controller endpoint")
	flag.StringVar(&clientFile, "clientFile", "clients.txt", "path to the file of clients")
	flag.BoolVar(&initialSetup, "initialSetup", false, "use for initial setup")
	flag.Parse()

	fmt.Printf("Enter your Unifi (https://unifi.ui.com/) username: ")
	fmt.Scan(&username)

	fmt.Printf("Enter your Unifi https://unifi.ui.com/) password: ")
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

	log.Printf("Refreshing current list of active clients")
	err = unifi.getActiveClients()
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

		if !strings.Contains(fields[1], `:`) {
			log.Printf("skipping line %q - appears to be malformed MAC address", s.Text())
			continue
		}

		if initialSetup {
			hc := &initialHomeClient{
				Name:                  strings.TrimSpace(fields[0]),
				Mac:                   strings.TrimSpace(fields[1]),
				FixedIP:               strings.TrimSpace(fields[2]),
				UseFixedip:            true,
				LocalDNSRecordEnabled: false,
			}

			err = unifi.initialClientSetup(hc)
			if err != nil {
				log.Fatalf("got error configuring client: %v", err)
			}
		} else {

			present := unifi.isActiveClient(strings.TrimSpace(fields[1]))
			if !present {
				log.Printf("Skipping update for %s - not an active client", strings.TrimSpace(fields[0]))
				continue
			}

			var macSlice []string
			macSlice = append(macSlice, strings.TrimSpace(fields[1]))

			removeC := &removeClient{
				Cmd:  "forget-sta",
				Macs: macSlice,
				Name: strings.TrimSpace(fields[0]),
			}

			err = unifi.removeClient(removeC)
			if err != nil {
				log.Fatalf("got error removing client: %v", err)
			}

			rc := &refreshClient{
				Name:       strings.TrimSpace(fields[0]),
				FixedIP:    strings.TrimSpace(fields[2]),
				UseFixedip: true,
			}

			err = unifi.refreshClient(rc)
			if err != nil {
				log.Fatalf("got error refreshing client: %v", err)
			}
		}

	}

	if err := s.Err(); err != nil {
		log.Fatalf("got error from scanner: %v", err)
	}

}
