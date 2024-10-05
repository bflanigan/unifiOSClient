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
	flag.StringVar(&endpoint, "endpoint", "https://192.168.1.1", "Controller endpoint")
	flag.StringVar(&clientFile, "clientFile", "", "path to the CSV of clients")
	flag.Parse()

	if len(clientFile) == 0 {
		log.Fatalf("you must specify the csv file with the clientFile option")
	}

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

	otp, ook := os.LookupEnv("UNIFIOTP")
	if ook {
		mfatoken = otp
	} else {
		fmt.Printf("Enter the MFA token: ")
		fmt.Scan(&mfatoken)
		fmt.Println()
	}

	unifi, err := newClient(endpoint, username, password, mfatoken)
	if err != nil {
		log.Fatalf("failed to construct unifi client: %v", err)
	}

	log.Printf("Refreshing current list of active clients and Unifi devices")
	fmt.Println()
	err = unifi.getActiveUnifiDevices()
	if err != nil {
		log.Fatalln(err)
	}

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
	fmt.Println()

	s := bufio.NewScanner(f)
	for s.Scan() {

		// log.Printf("examining line: %q", s.Text())

		valid := isValidLine(s.Text())
		if !valid {
			continue
		}

		fields := strings.Split(s.Text(), `,`)
		name := strings.TrimSpace(fields[0])
		mac := strings.TrimSpace(strings.ToLower(fields[1]))
		ipaddr := strings.TrimSpace(fields[2])

		present, isUnifi := unifi.isActiveClient(mac)
		if !present && !isUnifi {

			hc := &initialHomeClient{
				Name:                  name,
				Mac:                   mac,
				FixedIP:               ipaddr,
				UseFixedip:            true,
				LocalDNSRecordEnabled: false,
			}

			err = unifi.initialClientSetup(hc)
			if err != nil {
				log.Fatalf("got error adding client: %v", err)
			}
			continue
		}

		if !isUnifi {
			// client is active but it's not a Unifi device
			rc := &refreshClient{
				Name:       name,
				FixedIP:    ipaddr,
				UseFixedip: true,
				Mac:        mac,
			}

			err = unifi.refreshClient(rc)
			if err != nil {
				log.Fatalf("got error refreshing client: %v", err)
			}
			continue
		}

		// unifiDevice that is managed
		ac, err := unifi.clientFromMac(mac)
		if err != nil {
			log.Fatalf("did not find Unifi device in activeClient map: %v", err)
		}

		octets := strings.Split(ipaddr, `.`)
		octets[3] = "1"

		var gateway string
		for _, o := range octets {
			gateway = gateway + o + "."
		}

		// strip trailing . from gateway
		gateway = strings.Trim(gateway, `.`)

		// Unifi device is active and present
		rd := &refreshDevice{
			id:            ac.ID,
			Name:          name,
			MgmtNetworkID: ac.MgmtNetworkID,
			ConfigNetwork: struct {
				Type           string `json:"type,omitempty"`
				IP             string `json:"ip,omitempty"`
				Netmask        string `json:"netmask,omitempty"`
				Gateway        string `json:"gateway,omitempty"`
				DNS1           string `json:"dns1,omitempty"`
				DNS2           string `json:"dns2,omitempty"`
				Dnssuffix      string `json:"dnssuffix,omitempty"`
				BondingEnabled bool   `json:"bonding_enabled,omitempty"`
			}{
				Type:           "static",
				IP:             ipaddr,
				Netmask:        "255.255.255.0",
				DNS1:           "8.8.8.8",
				DNS2:           "",
				Dnssuffix:      "",
				BondingEnabled: false,
				Gateway:        gateway,
			},
		}

		err = unifi.refreshDevice(rd)
		if err != nil {
			log.Fatalf("failed to refresh Unifi device: %v", err)
		}
	}

	if err := s.Err(); err != nil {
		log.Fatalf("got error from scanner: %v", err)
	}

}

func isValidLine(s string) bool {

	if !strings.Contains(s, `,`) {
		// log.Printf("Skipping line %q - did not see comma delimited fields\n", s)
		return false
	}

	if strings.HasPrefix(s, `#`) {
		// log.Printf("Skipping line %q - commented out\n", s)
		return false
	}

	fields := strings.Split(s, `,`)

	if !strings.HasPrefix(fields[2], "192.168") {
		// log.Printf("Skipping line %q - did not see IP address starting with 192.168\n", s)
		return false
	}

	octets := strings.Split(fields[2], `.`)
	if len(octets) != 4 {
		// log.Printf("malformed IP address: %s", fields[2])
		return false
	}

	numFields := len(fields)
	if numFields <= 2 {
		// log.Printf("Skipping line %q - insufficient number of fields (%d)\n", s, numFields)
		return false

	}

	if !strings.Contains(fields[1], `:`) {
		// log.Printf("skipping line %q - appears to be malformed MAC address (%s)", s, fields[1])
		return false
	}

	return true
}
