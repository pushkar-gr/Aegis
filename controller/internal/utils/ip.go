package utils

import (
	"encoding/binary"
	"net"
	"net/http"
	"strings"
)

// IpToUint32 converts IP string to uint32 representation.
func IpToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	return binary.BigEndian.Uint32(ip4)
}

// Uint32ToIp converts uint32 to IP string representation.
func Uint32ToIp(nn uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip.String()
}

// GetClientIP extracts the real client IP from HTTP request headers.
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			clientIP := strings.TrimSpace(ips[0])
			if net.ParseIP(clientIP) != nil {
				return clientIP
			}
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		clientIP := strings.TrimSpace(xri)
		if net.ParseIP(clientIP) != nil {
			return clientIP
		}
	}

	// Fallback to RemoteAddr (strip port if present)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
