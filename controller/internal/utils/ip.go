package utils

import (
	"encoding/binary"
	"fmt"
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
	// Fallback to RemoteAddr (strip port if present)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	if isTrustedProxy(ip) {
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
	}

	return ip
}

var trustedProxyNets []*net.IPNet

func SetTrustedProxies(entries []string) error {
	nets := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return fmt.Errorf("invalid trusted proxy entry %q: not a valid IP or CIDR", e)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		_, n, err := net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), bits))
		if err != nil {
			return fmt.Errorf("invalid trusted proxy entry %q: %w", e, err)
		}
		nets = append(nets, n)
	}
	trustedProxyNets = nets
	return nil
}

func isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range trustedProxyNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// ResolveHostname looks up the IP addresses for a given hostname
func ResolveHostname(hostname string) ([]string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname %s: %w", hostname, err)
	}

	var ipStrings []string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipStrings = append(ipStrings, ipv4.String())
		}
	}

	if len(ipStrings) == 0 {
		return nil, fmt.Errorf("no IPv4 addresses found for hostname %s", hostname)
	}

	return ipStrings, nil
}
