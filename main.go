package main

import (
	"fmt"
)

type Host struct {
	IP        string
	OpenPorts []NmapPortInfo
	Vulns     []Vulnerability
	OS        string
}

func generateReport(hosts []Host) {
	fmt.Println("Scanning Report")
	fmt.Println("===============")
	for _, host := range hosts {
		fmt.Printf("IP Address: %s\n", host.IP)
		fmt.Printf("Detected OS: %s\n", host.OS)
		fmt.Println("Open Ports:")
		for _, port := range host.OpenPorts {
			fmt.Printf("  - %d/%s (%s)\n", port.Port, port.Protocol, port.Service.Name)
		}
		fmt.Println("Vulnerabilities:")
		for _, vuln := range host.Vulns {
			fmt.Printf("  - CVE: %s | Service: %s | Severity: %s | Description: %s\n", vuln.CVE, vuln.Service, vuln.Severity, vuln.Description)
		}
		fmt.Println("---------------")
	}
}

func main() {
	UserIIP, err := GetInternalIP() // Get internal IP address
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	println("My Internal IP: ", UserIIP)

	UserEIP, err := GetExternalIP() // Get external IP address
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	println("My External IP: ", UserEIP)

	liveHosts := scanIPRange("10.0.0.1", "10.0.0.255")
	var scannedHosts []Host

	println("Live hosts: ")
	for _, hostIP := range liveHosts {
		println("-", hostIP)
		host := &Host{
			IP:        hostIP,
			OpenPorts: scanPortsNmap(hostIP),
		}
		checkVulnerabilities(host)
		scannedHosts = append(scannedHosts, *host)
	}

	generateReport(scannedHosts)
}
