package main

import (
	"net"
	"strconv"
	"sync"
	"time"
)

func isPortOpen(ip string, port int) bool {
	// Simple check: attempt a TCP dial.
	target := ip + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", target, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// regular scanPorts function without nmap
// func scanPorts(ip string) []int {
// 	var wg sync.WaitGroup
// 	var mutex sync.Mutex
// 	var openPorts []int

// 	const startPort = 1   // Adjust as necessary
// 	const endPort = 65535 // Adjust as necessary

// 	for port := startPort; port <= endPort; port++ {
// 		wg.Add(1)
// 		go func(p int) {
// 			defer wg.Done()
// 			if isPortOpen(ip, p) {
// 				mutex.Lock()
// 				openPorts = append(openPorts, p)
// 				mutex.Unlock()
// 			}
// 		}(port)
// 	}
// 	wg.Wait()

// 	return openPorts
// }

func scanPortsNmap(ip string) []NmapPortInfo {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var openPortsInfo []NmapPortInfo

	const startPort = 1   // Adjust as necessary
	const endPort = 65535 // Adjust as necessary

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if isPortOpen(ip, p) {
				mutex.Lock()
				portInfo := NmapPortInfo{
					Port: p,
					// Since we're only using "tcp" in isPortOpen:
					Protocol: "tcp",
					// We don't know the service name from this function,
					// so keeping it blank.
					Service: NmapService{Name: ""},
				}
				openPortsInfo = append(openPortsInfo, portInfo)
				mutex.Unlock()
			}
		}(port)
	}
	wg.Wait()

	return openPortsInfo
}
