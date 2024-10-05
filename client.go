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
	ID            string
	MAC           string
	DisplayName   string
	HostName      string
	Model         string
	MgmtNetworkID string
	unifiDevice   bool
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
	Mac                           string
}

type refreshDevice struct {
	id            string
	Name          string `json:"name,omitempty"`
	ConfigNetwork struct {
		Type           string `json:"type,omitempty"`
		IP             string `json:"ip,omitempty"`
		Netmask        string `json:"netmask,omitempty"`
		Gateway        string `json:"gateway,omitempty"`
		DNS1           string `json:"dns1,omitempty"`
		DNS2           string `json:"dns2,omitempty"`
		Dnssuffix      string `json:"dnssuffix,omitempty"`
		BondingEnabled bool   `json:"bonding_enabled,omitempty"`
	} `json:"config_network,omitempty"`
	MgmtNetworkID              string `json:"mgmt_network_id,omitempty"`
	LedOverride                string `json:"led_override,omitempty"`
	LedOverrideColorBrightness int    `json:"led_override_color_brightness,omitempty"`
	LedOverrideColor           string `json:"led_override_color,omitempty"`
	SnmpContact                string `json:"snmp_contact,omitempty"`
	SnmpLocation               string `json:"snmp_location,omitempty"`
	StpPriority                string `json:"stp_priority,omitempty"`
	EtherLighting              struct {
	} `json:"ether_lighting,omitempty"`
}

type unifiDevices struct {
	AccessDevices  []any `json:"access_devices,omitempty"`
	ApolloDevices  []any `json:"apollo_devices,omitempty"`
	ConnectDevices []any `json:"connect_devices,omitempty"`
	LedDevices     []any `json:"led_devices,omitempty"`
	NetworkDevices []struct {
		ID                          string `json:"_id,omitempty"`
		AdoptState                  int    `json:"adopt_state,omitempty"`
		AdoptableWhenUpgraded       bool   `json:"adoptable_when_upgraded,omitempty"`
		Adopted                     bool   `json:"adopted,omitempty"`
		BytesR                      int    `json:"bytes-r,omitempty"`
		ConnectionNetworkID         string `json:"connection_network_id,omitempty"`
		ConnectionNetworkName       string `json:"connection_network_name,omitempty"`
		CountrycodeTable            []any  `json:"countrycode_table,omitempty"`
		Default                     bool   `json:"default,omitempty"`
		DeviceType                  string `json:"device_type,omitempty"`
		Disabled                    bool   `json:"disabled,omitempty"`
		DiscoveredVia               string `json:"discovered_via,omitempty"`
		DisplayableVersion          string `json:"displayable_version,omitempty"`
		DownloadSpeedBytesPerSecond int    `json:"download_speed_bytes_per_second,omitempty"`
		EthernetOverrides           []struct {
			Ifname       string `json:"ifname,omitempty"`
			Networkgroup string `json:"networkgroup,omitempty"`
		} `json:"ethernet_overrides,omitempty"`
		FwCaps                    int    `json:"fw_caps,omitempty"`
		IP                        string `json:"ip,omitempty"`
		IsAccessPoint             bool   `json:"is_access_point,omitempty"`
		IsAdoptionQueued          bool   `json:"is_adoption_queued,omitempty"`
		Isolated                  bool   `json:"isolated,omitempty"`
		LanIP                     string `json:"lan_ip,omitempty"`
		LastConnectionNetworkID   string `json:"last_connection_network_id,omitempty"`
		LastConnectionNetworkName string `json:"last_connection_network_name,omitempty"`
		LastSeen                  int    `json:"last_seen,omitempty"`
		LastUplink                struct {
			PortIdx   int    `json:"port_idx,omitempty"`
			Type      string `json:"type,omitempty"`
			UplinkMac string `json:"uplink_mac,omitempty"`
		} `json:"last_uplink,omitempty"`
		LicenseState      string `json:"license_state,omitempty"`
		Locating          bool   `json:"locating,omitempty"`
		LteConnected      bool   `json:"lte_connected,omitempty"`
		Mac               string `json:"mac,omitempty"`
		Model             string `json:"model,omitempty"`
		ModelInEol        bool   `json:"model_in_eol,omitempty"`
		ModelInLts        bool   `json:"model_in_lts,omitempty"`
		ModelIncompatible bool   `json:"model_incompatible,omitempty"`
		Name              string `json:"name,omitempty"`
		NumSta            int    `json:"num_sta,omitempty"`
		PortTable         []struct {
			AggregatedBy bool   `json:"aggregated_by,omitempty"`
			Autoneg      bool   `json:"autoneg,omitempty"`
			Enable       bool   `json:"enable,omitempty"`
			FullDuplex   bool   `json:"full_duplex,omitempty"`
			Ifname       string `json:"ifname,omitempty"`
			IP           string `json:"ip,omitempty"`
			IsUplink     bool   `json:"is_uplink,omitempty"`
			Media        string `json:"media,omitempty"`
			Name         string `json:"name,omitempty"`
			PoeCaps      int    `json:"poe_caps,omitempty"`
			PoeEnable    bool   `json:"poe_enable,omitempty"`
			PortIdx      int    `json:"port_idx,omitempty"`
			PortPoe      bool   `json:"port_poe,omitempty"`
			RxBytes      int    `json:"rx_bytes,omitempty"`
			RxBytesR     int    `json:"rx_bytes-r,omitempty"`
			RxDropped    int    `json:"rx_dropped,omitempty"`
			RxErrors     int    `json:"rx_errors,omitempty"`
			RxPackets    int    `json:"rx_packets,omitempty"`
			Satisfaction int    `json:"satisfaction,omitempty"`
			Speed        int    `json:"speed,omitempty"`
			SpeedCaps    int    `json:"speed_caps,omitempty"`
			TxBytes      int    `json:"tx_bytes,omitempty"`
			TxBytesR     int    `json:"tx_bytes-r,omitempty"`
			TxDropped    int    `json:"tx_dropped,omitempty"`
			TxErrors     int    `json:"tx_errors,omitempty"`
			TxPackets    int    `json:"tx_packets,omitempty"`
			Up           bool   `json:"up,omitempty"`
			OpMode       string `json:"op_mode,omitempty"`
		} `json:"port_table,omitempty"`
		ProductLine      string `json:"product_line,omitempty"`
		RadioTable       []any  `json:"radio_table,omitempty"`
		RadioTableStats  []any  `json:"radio_table_stats,omitempty"`
		Restarting       bool   `json:"restarting,omitempty"`
		RxBytes          int    `json:"rx_bytes,omitempty"`
		RxBytesD         int    `json:"rx_bytes-d,omitempty"`
		Satisfaction     int    `json:"satisfaction,omitempty"`
		SpectrumScanning bool   `json:"spectrum_scanning,omitempty"`
		State            int    `json:"state,omitempty"`
		SysStats         struct {
			Loadavg1  float64 `json:"loadavg_1,omitempty"`
			Loadavg15 float64 `json:"loadavg_15,omitempty"`
			Loadavg5  float64 `json:"loadavg_5,omitempty"`
			MemBuffer int     `json:"mem_buffer,omitempty"`
			MemTotal  int64   `json:"mem_total,omitempty"`
			MemUsed   int     `json:"mem_used,omitempty"`
		} `json:"sys_stats,omitempty"`
		SystemStats struct {
			CPU    float64 `json:"cpu,omitempty"`
			Mem    float64 `json:"mem,omitempty"`
			Uptime int     `json:"uptime,omitempty"`
		} `json:"system-stats,omitempty"`
		TxBytes           int    `json:"tx_bytes,omitempty"`
		TxBytesD          int    `json:"tx_bytes-d,omitempty"`
		Type              string `json:"type,omitempty"`
		Unsupported       bool   `json:"unsupported,omitempty"`
		UnsupportedReason int    `json:"unsupported_reason,omitempty"`
		Upgradable        bool   `json:"upgradable,omitempty"`
		UpgradeState      int    `json:"upgrade_state,omitempty"`
		Uplink            struct {
			Name      string `json:"name,omitempty"`
			PortIdx   int    `json:"port_idx,omitempty"`
			Speed     int    `json:"speed,omitempty"`
			Type      string `json:"type,omitempty"`
			UplinkMac string `json:"uplink_mac,omitempty"`
		} `json:"uplink,omitempty"`
		UplinkTable                         []any   `json:"uplink_table,omitempty"`
		UploadSpeedBytesPerSecond           int     `json:"upload_speed_bytes_per_second,omitempty"`
		Uptime                              int     `json:"uptime,omitempty"`
		UsageBytes                          float64 `json:"usage_bytes,omitempty"`
		VapTable                            []any   `json:"vap_table,omitempty"`
		Version                             string  `json:"version,omitempty"`
		Ipv4LeaseExpirationTimestampSeconds int     `json:"ipv4_lease_expiration_timestamp_seconds,omitempty"`
		LastUplink0                         struct {
			PortIdx          int    `json:"port_idx,omitempty"`
			Type             string `json:"type,omitempty"`
			UplinkDeviceName string `json:"uplink_device_name,omitempty"`
			UplinkMac        string `json:"uplink_mac,omitempty"`
			UplinkRemotePort int    `json:"uplink_remote_port,omitempty"`
		} `json:"last_uplink,omitempty"`
		Uplink0 struct {
			Mac              string `json:"mac,omitempty"`
			Name             string `json:"name,omitempty"`
			PortIdx          int    `json:"port_idx,omitempty"`
			Speed            int    `json:"speed,omitempty"`
			Type             string `json:"type,omitempty"`
			UplinkDeviceName string `json:"uplink_device_name,omitempty"`
			UplinkMac        string `json:"uplink_mac,omitempty"`
			UplinkRemotePort int    `json:"uplink_remote_port,omitempty"`
		} `json:"uplink,omitempty"`
	} `json:"network_devices,omitempty"`
	ProtectDevices   []any `json:"protect_devices,omitempty"`
	TalkDevices      []any `json:"talk_devices,omitempty"`
	UnmanagedDevices []any `json:"unmanaged_devices,omitempty"`
}

// type removeClient struct {
// 	Macs []string `json:"macs"`
// 	Cmd  string   `json:"cmd"`
// 	name string
// }

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
		u.activeClients[a.MAC] = a
		log.Printf("Found active client - DisplayName %q HostName: %q MAC: %s and ID: %s", a.DisplayName, a.HostName, a.MAC, a.ID)
	}
	fmt.Println()

	return nil
}

func (u *unifiClient) getActiveUnifiDevices() error {

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/proxy/network/v2/api/site/default/device", u.endpoint), nil)
	if err != nil {
		return fmt.Errorf("failed to construct active device list request: %v", err)
	}
	u.decorateRequest(req, false)

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("got error making active device list: %v", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		log.Printf("Response body: %v", string(b))
		return fmt.Errorf("did not get HTTP 200 listing devices")
	}

	var devices unifiDevices

	err = json.Unmarshal(b, &devices)
	if err != nil {
		return err
	}

	for _, c := range devices.NetworkDevices {

		if c.Model == "UCGMAX" {
			// don't screw ourselves and make changes to the gateway
			// do this in the UI
			continue
		}

		if c.DeviceType != "MANAGED" {
			// don't touch unmanaged devices
			log.Printf("Skipping unmanaged Unifi Device - DisplayName %q Model: %s MAC: %s", c.Name, c.Model, c.Mac)
			continue
		}

		a := activeClient{
			MAC:           strings.ToLower(c.Mac),
			ID:            c.ID,
			DisplayName:   c.Name,
			Model:         c.Model,
			MgmtNetworkID: c.ConnectionNetworkID,
			unifiDevice:   true,
		}
		u.activeClients[c.Mac] = a
		log.Printf("Found Unifi Device - DisplayName %q Model: %s MAC: %s and ID: %s", a.DisplayName, a.Model, a.MAC, a.ID)
	}
	fmt.Println()

	return nil
}

func (u *unifiClient) isActiveClient(mac string) (bool, bool) {
	// check if the MAC address is in the list of active clients
	for _, v := range u.activeClients {
		if v.MAC == mac {
			return true, v.unifiDevice
		}
	}
	return false, false
}

func (u *unifiClient) clientFromMac(mac string) (*activeClient, error) {

	for _, v := range u.activeClients {
		if v.MAC == mac {
			return &v, nil
		}
	}
	return nil, fmt.Errorf("did not find MAC in active client list")
}

func (u *unifiClient) decorateRequest(req *http.Request, omitCSRFToken bool) {
	req.Header.Add("content-type", "application/json")
	req.Header.Add("accept", "*/*")

	if !omitCSRFToken {
		req.Header.Add("x-csrf-token", u.csrfToken)
	}
}

func (u *unifiClient) initialClientSetup(h *initialHomeClient) error {

	log.Printf("Adding home client: %s / %s / %s", h.Name, h.FixedIP, h.Mac)
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/proxy/network/api/s/default/rest/user", u.endpoint), bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("failed to construct client add request: %v", err)
	}
	u.decorateRequest(req, false)

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("got error adding client: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bodyResponse, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if strings.Contains(string(bodyResponse), "api.err.MacUsed") {
			log.Printf("%s / %s / %s was already added, skipping", h.Name, h.FixedIP, h.Mac)
			return nil
		}

		if strings.Contains(string(bodyResponse), "api.err.InvalidFixedIP") {
			log.Printf("%s / %s / %s failed to add - did you setup the additional network for this client yet?", h.Name, h.FixedIP, h.Mac)
			log.Printf("Failure response body: %v", string(bodyResponse))
		} else {
			log.Printf("Failure response body: %v", string(bodyResponse))
		}

		return fmt.Errorf("did not get HTTP 200 adding client")
	}

	return nil
}

func (u *unifiClient) refreshClient(h *refreshClient) error {

	log.Printf("Refreshing home client: %s / %s / %s", h.Name, h.FixedIP, h.Mac)
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}

	var ID string
	for _, v := range u.activeClients {
		if v.MAC == h.Mac {
			ID = v.ID
		}
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/proxy/network/api/s/default/rest/user/%s", u.endpoint, ID), bytes.NewReader(b))
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

func (u *unifiClient) refreshDevice(h *refreshDevice) error {

	log.Printf("Refreshing Unifi device: %s", h.Name)
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}

	// var ID string
	// for _, v := range u.activeClients {
	// 	if v.MAC == h.Mac {
	// 		ID = v.ID
	// 	}
	// }

	//TODO need to get ID of device

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/proxy/network/api/s/default/rest/device/%s", u.endpoint, h.id), bytes.NewReader(b))
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

// func (u *unifiClient) removeClient(h *removeClient) error {

// 	log.Printf("Removing client with MAC: %s\n", h.Macs[0])
// 	b, err := json.Marshal(h)
// 	if err != nil {
// 		return err
// 	}

// 	req, err := http.NewRequest("POST", fmt.Sprintf("%s/proxy/network/api/s/default/cmd/stamgr", u.endpoint), bytes.NewReader(b))
// 	if err != nil {
// 		return fmt.Errorf("failed to construct client removal request: %v", err)
// 	}
// 	u.decorateRequest(req, false)

// 	resp, err := u.client.Do(req)
// 	if err != nil {
// 		return fmt.Errorf("got error removing client: %v", err)
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != 200 {
// 		bodyResponse, err := io.ReadAll(resp.Body)
// 		if err != nil {
// 			return err
// 		}

// 		log.Printf("Failure response body: %v", string(bodyResponse))
// 		return fmt.Errorf("did not get HTTP 200 removing client")
// 	}

// 	return nil
// }
