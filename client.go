package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
)

type unifiClient struct {
	client    *http.Client
	csrfToken string
	endpoint  string

	activeClients map[string]activeClient
}

type activeClient struct {
	ID          string
	MAC         string
	DisplayName string
	HostName    string
}

type login struct {
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Token      string `json:"token,omitempty"`
	RememberMe bool   `json:"rememberMe,omitempty"`
}

type initialHomeClient struct {
	Mac                   string `json:"mac"`
	Name                  string `json:"name"`
	UseFixedip            bool   `json:"use_fixedip"`
	LocalDNSRecordEnabled bool   `json:"local_dns_record_enabled"`
	FixedIP               string `json:"fixed_ip"`
}

type refreshClient struct {
	LocalDNSRecordEnabled         bool   `json:"local_dns_record_enabled"`
	LocalDNSRecord                string `json:"local_dns_record"`
	Name                          string `json:"name"`
	VirtualNetworkOverrideEnabled bool   `json:"virtual_network_override_enabled"`
	VirtualNetworkOverrideID      string `json:"virtual_network_override_id"`
	UsergroupID                   string `json:"usergroup_id"`
	UseFixedip                    bool   `json:"use_fixedip"`
	FixedIP                       string `json:"fixed_ip"`
}

type removeClient struct {
	Macs []string `json:"macs"`
	Cmd  string   `json:"cmd"`
	Name string
}

type unifiHomeClient []struct {
	Anomalies   int    `json:"anomalies,omitempty"`
	AssocTime   int    `json:"assoc_time,omitempty"`
	Blocked     bool   `json:"blocked,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Fingerprint struct {
		ComputedDevID  int  `json:"computed_dev_id,omitempty"`
		ComputedEngine int  `json:"computed_engine,omitempty"`
		Confidence     int  `json:"confidence,omitempty"`
		DevCat         int  `json:"dev_cat,omitempty"`
		DevFamily      int  `json:"dev_family,omitempty"`
		DevID          int  `json:"dev_id,omitempty"`
		DevVendor      int  `json:"dev_vendor,omitempty"`
		HasOverride    bool `json:"has_override,omitempty"`
		OsName         int  `json:"os_name,omitempty"`
	} `json:"fingerprint,omitempty"`
	FirstSeen                           int     `json:"first_seen,omitempty"`
	FixedIP                             string  `json:"fixed_ip,omitempty"`
	GwMac                               string  `json:"gw_mac,omitempty"`
	Hostname                            string  `json:"hostname,omitempty"`
	ID                                  string  `json:"id,omitempty"`
	IP                                  string  `json:"ip,omitempty"`
	Ipv4LeaseExpirationTimestampSeconds int     `json:"ipv4_lease_expiration_timestamp_seconds,omitempty"`
	IsAllowedInVisualProgramming        bool    `json:"is_allowed_in_visual_programming,omitempty"`
	IsGuest                             bool    `json:"is_guest,omitempty"`
	IsWired                             bool    `json:"is_wired,omitempty"`
	LastSeen                            int     `json:"last_seen,omitempty"`
	LastUplinkMac                       string  `json:"last_uplink_mac,omitempty"`
	LastUplinkName                      string  `json:"last_uplink_name,omitempty"`
	LatestAssocTime                     int     `json:"latest_assoc_time,omitempty"`
	LocalDNSRecord                      string  `json:"local_dns_record,omitempty"`
	LocalDNSRecordEnabled               bool    `json:"local_dns_record_enabled,omitempty"`
	Mac                                 string  `json:"mac,omitempty"`
	Name                                string  `json:"name,omitempty"`
	NetworkID                           string  `json:"network_id,omitempty"`
	NetworkName                         string  `json:"network_name,omitempty"`
	Noted                               bool    `json:"noted,omitempty"`
	Oui                                 string  `json:"oui,omitempty"`
	RxBytes                             int     `json:"rx_bytes,omitempty"`
	RxPackets                           int     `json:"rx_packets,omitempty"`
	SiteID                              string  `json:"site_id,omitempty"`
	Status                              string  `json:"status,omitempty"`
	SwPort                              int     `json:"sw_port,omitempty"`
	TxBytes                             int     `json:"tx_bytes,omitempty"`
	TxPackets                           int     `json:"tx_packets,omitempty"`
	Type                                string  `json:"type,omitempty"`
	UnifiDevice                         bool    `json:"unifi_device,omitempty"`
	UplinkMac                           string  `json:"uplink_mac,omitempty"`
	Uptime                              int     `json:"uptime,omitempty"`
	UsageBytes                          float64 `json:"usage_bytes,omitempty"`
	UseFixedip                          bool    `json:"use_fixedip,omitempty"`
	UserID                              string  `json:"user_id,omitempty"`
	UsergroupID                         string  `json:"usergroup_id,omitempty"`
	VirtualNetworkOverrideEnabled       bool    `json:"virtual_network_override_enabled,omitempty"`
	VirtualNetworkOverrideID            string  `json:"virtual_network_override_id,omitempty"`
	WiredRateMbps                       int     `json:"wired_rate_mbps,omitempty"`
}

func newClient(endpoint, username, password, mfatoken string) (*unifiClient, error) {

	u := &unifiClient{}

	loginPayload := login{
		Username: username,
		Password: password,
		Token:    mfatoken,
	}

	loginBody, err := json.Marshal(loginPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login: %v", err)
	}

	jar, _ := cookiejar.New(nil)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
		Jar:       jar,
	}

	loginReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/auth/login", endpoint), bytes.NewReader(loginBody))
	if err != nil {
		return nil, fmt.Errorf("failed to construct request: %v", err)
	}
	u.decorateRequest(loginReq, true)

	resp, err := client.Do(loginReq)
	if err != nil {
		return nil, fmt.Errorf("got error making login request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to login to controller, check password")
	}

	csrfToken := resp.Header.Get("X-Csrf-Token")
	if len(csrfToken) == 0 {
		return nil, fmt.Errorf("did not find X-Csrf-Token in response")
	}

	return &unifiClient{
		client:        client,
		csrfToken:     csrfToken,
		endpoint:      endpoint,
		activeClients: make(map[string]activeClient),
	}, nil

}

func (u *unifiClient) getActiveClients() error {

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/proxy/network/v2/api/site/default/clients/active", u.endpoint), nil)
	if err != nil {
		return fmt.Errorf("failed to construct active client list request: %v", err)
	}
	u.decorateRequest(req, false)

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("got error making active client list: %v", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		log.Printf("Response body: %v", string(b))
		return fmt.Errorf("did not get HTTP 200 updating client")
	}

	var clients unifiHomeClient

	err = json.Unmarshal(b, &clients)
	if err != nil {
		return err
	}

	for _, c := range clients {
		a := activeClient{
			MAC:         strings.ToLower(c.Mac),
			ID:          c.UserID,
			DisplayName: c.DisplayName,
			HostName:    c.Hostname,
		}
		u.activeClients[c.DisplayName] = a
		log.Printf("DisplayName %q HostName: %q MAC: %s and ID: %s", a.DisplayName, a.HostName, a.MAC, a.ID)
	}
	fmt.Println()

	return nil
}

func (u *unifiClient) decorateRequest(req *http.Request, omitCSRFToken bool) {
	req.Header.Add("content-type", "application/json")
	req.Header.Add("accept", "*/*")

	if !omitCSRFToken {
		req.Header.Add("x-csrf-token", u.csrfToken)
	}
}

func (u *unifiClient) initialClientSetup(h *initialHomeClient) error {

	log.Printf("Configuring home client: %s\n", h.Name)
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/proxy/network/api/s/default/rest/user", u.endpoint), bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("failed to construct client update request: %v", err)
	}
	u.decorateRequest(req, false)

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("got error updating client: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyResponse, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if strings.Contains(string(bodyResponse), "api.err.MacUsed") {
			log.Printf("%s was already configured, skipping", h.Name)
			return nil
		}

		log.Printf("Failure response body: %v", string(bodyResponse))
		return fmt.Errorf("did not get HTTP 200 updating client")
	}

	return nil
}

func (u *unifiClient) refreshClient(h *refreshClient) error {

	log.Printf("Refreshing home client: %s\n", h.Name)
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/proxy/network/api/s/default/rest/user/%s", u.endpoint, info.ID), bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("failed to construct client refresh request: %v", err)
	}
	u.decorateRequest(req, false)

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("got error refreshing client: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyResponse, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		log.Printf("Failure response body: %v", string(bodyResponse))
		return fmt.Errorf("did not get HTTP 200 refreshing client")
	}

	return nil
}

func (u *unifiClient) removeClient(h *removeClient) error {

	log.Printf("Removing home client: %s\n", h.Name)
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/proxy/network/api/s/default/cmd/stamgr", u.endpoint), bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("failed to construct client removal request: %v", err)
	}
	u.decorateRequest(req, false)

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("got error removing client: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyResponse, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		log.Printf("Failure response body: %v", string(bodyResponse))
		return fmt.Errorf("did not get HTTP 200 removing client")
	}

	return nil
}

func (u *unifiClient) isActiveClient(mac string) bool {
	// check if the client is in the list of active clients
	for _, v := range u.activeClients {
		if v.MAC == mac {
			return true
		}
	}
	return false
}
