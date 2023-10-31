package main

import (
	"fmt"
	"sync"
	"time"
)

type Host struct {
	IP        string
	OpenPorts []NmapPortInfo
	Vulns     []Vulnerability
	OS        string
}

func generateReport(hosts []Host) {
	// Generate a report of the scan results.
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

func loadingAnimation(done chan bool) {
	animationChars := []string{"-", "\\", "|", "/"}
	i := 0
	for {
		select {
		case <-done:
			fmt.Printf("\rDone scanning! \n")
			return
		default:
			fmt.Printf("\rScanning... %s", animationChars[i%len(animationChars)])
			i++
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func main() {
	UserIIP, err := GetInternalIP() // Get internal IP address
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	fmt.Println("My Internal IP: ", UserIIP)

	UserEIP, err := GetExternalIP() // Get external IP address
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}
	fmt.Println("My External IP: ", UserEIP)

	liveHosts := scanIPRange("10.0.0.1", "10.0.0.255")
	var scannedHosts []Host

	fmt.Println("Live hosts: ")
	var wg sync.WaitGroup
	var mutex sync.Mutex
	for _, hostIP := range liveHosts {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			host := &Host{
				IP:        ip,
				OpenPorts: scanPortsNmap(ip),
			}
			checkVulnerabilities(host)
			mutex.Lock()
			scannedHosts = append(scannedHosts, *host)
			mutex.Unlock()
		}(hostIP)
	}

	// Start loading animation in a separate goroutine
	done := make(chan bool)
	go loadingAnimation(done)

	// Wait for all scanning goroutines to finish
	wg.Wait()
	done <- true // Stop the loading animation

	generateReport(scannedHosts)
}
