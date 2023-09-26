package main

import (
	"net"
	"strconv"
	"sync"
	"time"
)

func IPtoInt(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	ip = ip.To4()
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

func InttoIP(intIP uint32) string {
	return strconv.Itoa(int(intIP>>24&0xFF)) + "." + strconv.Itoa(int(intIP>>16&0xFF)) + "." +
		strconv.Itoa(int(intIP>>8&0xFF)) + "." + strconv.Itoa(int(intIP&0xFF))
}

func isHostAlive(ip string) bool {
	// Simple check: attempt a TCP dial (e.g., on port 80).
	// Adjust the timeout and port as necessary.
	conn, err := net.DialTimeout("tcp", ip+":80", 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func scanIPRange(startIP string, endIP string) []string {
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var liveHosts []string

	startInt := IPtoInt(startIP)
	endInt := IPtoInt(endIP)

	for i := startInt; i <= endInt; i++ {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if isHostAlive(ip) {
				mutex.Lock()
				liveHosts = append(liveHosts, ip)
				mutex.Unlock()
			}
		}(InttoIP(i))
	}
	wg.Wait()

	return liveHosts
}
