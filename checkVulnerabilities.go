package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"os/exec"
)

type Vulnerability struct {
	Port        int
	Service     string
	Description string
	Severity    string
	CVE         string
}

type CVEDetail struct {
	CVE            string `json:"cve"`
	Summary        string `json:"summary"`
	Severity       string `json:"severity"`
	ServiceVersion string `json:"version"`
}

type NVDCveResponse struct {
	Result NVDCveResult `json:"result"`
}

type NVDCveResult struct {
	CVEItems []NVDCveItem `json:"CVE_Items"`
}

type NVDCveItem struct {
	Cve NVDCveData `json:"cve"`
}

type NVDCveData struct {
	Meta NVDCveMetaData `json:"CVE_data_meta"`
	Des  NVDCveDesc     `json:"description"`
}

type NVDCveMetaData struct {
	ID string `json:"ID"`
}

type NVDCveDesc struct {
	DescData []NVDCveDescData `json:"description_data"`
}

type NVDCveDescData struct {
	Language string `json:"lang"`
	Value    string `json:"value"`
}

// using the NVD API for vulnerabilities check
func getVulnerabilitiesForService(serviceName string, serviceVersion string) []Vulnerability {
	var vulns []Vulnerability

	apiURL := "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + serviceName
	response, err := http.Get(apiURL)
	if err != nil {
		fmt.Println("Error fetching data:", err)
		return vulns
	}
	defer response.Body.Close()

	var cveResponse NVDCveResponse
	if err := json.NewDecoder(response.Body).Decode(&cveResponse); err != nil {
		fmt.Println("Error decoding response:", err)
		return vulns
	}

	for _, cveItem := range cveResponse.Result.CVEItems {
		vulns = append(vulns, Vulnerability{
			Service:     serviceName,
			Description: cveItem.Cve.Des.DescData[0].Value, // Assuming at least one description exists and using the first one.
			CVE:         cveItem.Cve.Meta.ID,
		})
	}

	return vulns
}

type NmapRun struct {
	Hosts []NmapHost `xml:"host"`
}

type NmapHost struct {
	Addresses []NmapAddress  `xml:"address"`
	Ports     []NmapPortInfo `xml:"ports>port"`
	OSMatches []NmapOSMatch  `xml:"os>osmatch"`
}

type NmapAddress struct {
	Addr string `xml:"addr,attr"`
}

type NmapService struct {
	Name string `xml:"name,attr"`
}

type NmapPortInfo struct {
	Port     int         `xml:"portid,attr"`
	Protocol string      `xml:"protocol,attr"`
	Service  NmapService `xml:"service"`
}

type NmapOSMatch struct {
	Name string `xml:"name,attr"`
}

func checkVulnerabilities(host *Host) {
	// Check for vulnerabilities on the host.
	out, err := exec.Command("nmap", "-p-", "-sV", "--osscan-guess", "--max-retries", "1", "--max-scan-delay", "20ms", "--open", "-oX", "-", host.IP).Output()
	if err != nil {
		panic(err)
	}

	for _, portInfo := range host.OpenPorts {
		vulns := getVulnerabilitiesForService(portInfo.Service.Name, "") // Assuming service version isn't captured.
		host.Vulns = append(host.Vulns, vulns...)
	}

	var nmapRun NmapRun
	err = xml.Unmarshal(out, &nmapRun)
	if err != nil {
		panic(err)
	}

	if len(nmapRun.Hosts) == 0 {
		return
	}

	// Get the OS information from Nmap's OS scan
	nmapHost := nmapRun.Hosts[0]
	if len(nmapHost.OSMatches) > 0 {
		host.OS = nmapHost.OSMatches[0].Name
	}
}
