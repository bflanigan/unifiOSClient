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

	user, ok := os.LookupEnv("UNIFIUSER")
	if ok {
		username = user
	} else {
		fmt.Printf("Enter your Unifi (https://unifi.ui.com/) username: ")
		fmt.Scan(&username)
	}

	pass, pok := os.LookupEnv("UNIFIPASS")
	if pok {
		password = pass
	} else {
		fmt.Printf("Enter your Unifi https://unifi.ui.com/) password: ")
		b, err := term.ReadPassword(0)
		if err != nil {
			log.Fatalln(err)
		}
		password = string(b)
		fmt.Println()
	}

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
	fmt.Println()

	f, err := os.Open(clientFile)
	if err != nil {
		log.Fatalf("failed to open clientFile: %v", err)
	}
	defer f.Close()

	log.Printf("Reading file with clients: %s", clientFile)

	s := bufio.NewScanner(f)
	for s.Scan() {

		valid := isValidLine(s.Text())
		if !valid {
			continue
		}

		fields := strings.Fields(s.Text())
		name := strings.TrimSpace(fields[0])
		mac := strings.TrimSpace(strings.ToLower(fields[1]))
		ipaddr := strings.TrimSpace(fields[2])

		if initialSetup {

			hc := &initialHomeClient{
				Name:                  name,
				Mac:                   mac,
				FixedIP:               ipaddr,
				UseFixedip:            true,
				LocalDNSRecordEnabled: false,
			}

			err = unifi.initialClientSetup(hc)
			if err != nil {
				log.Fatalf("got error configuring client: %v", err)
			}

		} else {

			present := unifi.isActiveClient(mac)
			if !present {
				log.Printf("Skipping update for %s - not an active client", name)
				continue
			}

			var macSlice []string
			macSlice = append(macSlice, mac)

			removeC := &removeClient{
				Cmd:  "forget-sta",
				Macs: macSlice,
				Name: name,
			}

			err = unifi.removeClient(removeC)
			if err != nil {
				log.Fatalf("got error removing client: %v", err)
			}

			hc := &initialHomeClient{
				Name:                  name,
				Mac:                   mac,
				FixedIP:               ipaddr,
				UseFixedip:            true,
				LocalDNSRecordEnabled: false,
			}

			err = unifi.initialClientSetup(hc)
			if err != nil {
				log.Fatalf("got error configuring client: %v", err)
			}

			// rc := &refreshClient{
			// 	Name:       name,
			// 	FixedIP:    ipaddr,
			// 	UseFixedip: true,
			// 	Mac:        mac,
			// }

			// err = unifi.refreshClient(rc)
			// if err != nil {
			// 	log.Fatalf("got error refreshing client: %v", err)
			// }
		}
	}

	if err := s.Err(); err != nil {
		log.Fatalf("got error from scanner: %v", err)
	}

}

func isValidLine(s string) bool {

	if !strings.Contains(s, "192.168") {
		log.Printf("Skipping line %q - did not see IP address starting with 192.168\n", s)
		return false
	}

	fields := strings.Fields(s)
	numFields := len(fields)
	if numFields <= 2 {
		log.Printf("Skipping line %q - insufficient number of fields (%d)\n", s, numFields)
		return false

	}

	if !strings.Contains(fields[1], `:`) {
		log.Printf("skipping line %q - appears to be malformed MAC address (%s)", s, fields[1])
		return false
	}

	return true
}
