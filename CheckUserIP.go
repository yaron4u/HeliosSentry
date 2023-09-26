package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

func GetInternalIP() (string, error) { // Get internal IP address
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", fmt.Errorf("no internal IP found")
}

func GetExternalIP() (string, error) { // Get external IP address
	resp, err := http.Get("https://httpbin.org/ip")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var ipResponse struct {
		Origin string `json:"origin"`
	}

	err = json.NewDecoder(resp.Body).Decode(&ipResponse)
	if err != nil {
		return "", err
	}

	return ipResponse.Origin, nil
}
