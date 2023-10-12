package main

import (
	"net"
	"strconv"
	"sync"
	"time"
)

func IPtoInt(ipStr string) uint32 {
	// Convert an IP address string to an integer.
	ip := net.ParseIP(ipStr)
	ip = ip.To4()
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

func InttoIP(intIP uint32) string {
	// Convert an integer to an IP address string.
	return strconv.Itoa(int(intIP>>24&0xFF)) + "." + strconv.Itoa(int(intIP>>16&0xFF)) + "." +
		strconv.Itoa(int(intIP>>8&0xFF)) + "." + strconv.Itoa(int(intIP&0xFF))
}

func isHostAlive(ip string) bool {
	// Check if a host is alive by pinging it.
	// Use a shorter timeout for a faster response.
	timeout := 500 * time.Millisecond

	// Pinging on multiple common ports to increase the accuracy of the live check.
	ports := []string{"22", "80", "443", "3389"}

	for _, port := range ports {
		conn, err := net.DialTimeout("tcp", ip+":"+port, timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func scanIPRange(startIP string, endIP string) []string {
	// Scan a range of IP addresses and return a list of live hosts.
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var liveHosts []string

	startInt := IPtoInt(startIP)
	endInt := IPtoInt(endIP)

	// Using buffered channels to control the number of concurrent goroutines.
	// This is to prevent spawning too many goroutines which might hamper performance.
	const maxGoroutines = 100
	goroutineSem := make(chan struct{}, maxGoroutines)

	for i := startInt; i <= endInt; i++ {
		goroutineSem <- struct{}{} // Acquire a token
		wg.Add(1)

		go func(ip string) {
			defer wg.Done()
			if isHostAlive(ip) {
				mutex.Lock()
				liveHosts = append(liveHosts, ip)
				mutex.Unlock()
			}
			<-goroutineSem // Release the token
		}(InttoIP(i))
	}

	wg.Wait()
	return liveHosts
}
