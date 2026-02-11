package watcher

import (
	"Aegis/controller/database"
	"context"
	"fmt"
	"log"
	"net"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// StartDockerWatcher listens for container events and updates service IPs in realtime
func StartDockerWatcher() {
	// Initialize Docker Client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("[WARN] Docker watcher: failed to create client: %v. Relying on DNS polling.", err)
		return
	}
	defer func() { _ = cli.Close() }()

	// Verify connection
	if _, err := cli.Ping(context.Background()); err != nil {
		log.Printf("[WARN] Docker watcher: cannot connect to Docker socket: %v. Relying on DNS polling.", err)
		return
	}

	log.Println("[INFO] Docker watcher started. Listening for real-time container updates...")

	// Filter for container 'start' events
	filterArgs := filters.NewArgs()
	filterArgs.Add("type", "container")
	filterArgs.Add("event", "start")

	msgChan, errChan := cli.Events(context.Background(), events.ListOptions{
		Filters: filterArgs,
	})

	for {
		select {
		case err := <-errChan:
			log.Printf("[ERROR] Docker event listener failed: %v", err)
			return
		case msg := <-msgChan:
			handleContainerEvent(cli, msg)
		}
	}
}

// handleContainerEvent hanles a container event by getting its hostname and checking with existing hostnames, if found it will udpate the ip
func handleContainerEvent(cli *client.Client, msg events.Message) {
	containerName := msg.Actor.Attributes["name"]
	if containerName == "" {
		return
	}

	// Check if there is any service using the container name as a hostname
	serviceID, currentIP, currentPort, servicePort, err := findServiceByHostnamePrefix(containerName)
	if err != nil {
		return
	}

	json, err := cli.ContainerInspect(context.Background(), msg.ID)
	if err != nil {
		log.Printf("[WARN] Docker watcher: failed to inspect container %s: %v", containerName, err)
		return
	}

	// Extract IP address
	var newIPStr string
	for _, network := range json.NetworkSettings.Networks {
		if network.IPAddress != "" {
			newIPStr = network.IPAddress
			break
		}
	}

	if newIPStr == "" {
		log.Printf("[WARN] Docker watcher: container %s started but has no IP", containerName)
		return
	}

	// Convert new IP to uint32
	newIP := ipToUint32(newIPStr)

	// Parse port
	portNum, err := net.LookupPort("tcp", servicePort)
	if err != nil {
		log.Printf("[WARN] Docker watcher: invalid port %s: %v", servicePort, err)
		return
	}
	newPort := uint16(portNum)

	if newIP != currentIP || newPort != currentPort {
		currentIPStr := uint32ToIp(currentIP)
		log.Printf("[INFO] Docker Event: Container '%s' started. Updating Service %d IP: %s:%d -> %s:%d",
			containerName, serviceID, currentIPStr, currentPort, newIPStr, newPort)

		_, err := database.DB.Exec("UPDATE services SET ip = ?, port = ? WHERE id = ?", newIP, newPort, serviceID)
		if err != nil {
			log.Printf("[ERROR] Docker watcher: failed to update DB: %v", err)
		}
	}
}

// ipToUint32 converts an IP string to uint32 (network byte order)
func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIp converts uint32 (network byte order) to IP string
func uint32ToIp(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

// findServiceByHostnamePrefix checks if any registered service matches the container name.
func findServiceByHostnamePrefix(containerName string) (int, uint32, uint16, string, error) {
	rows, err := database.DB.Query("SELECT id, hostname, ip, port FROM services")
	if err != nil {
		return 0, 0, 0, "", err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var id int
		var hostname string
		var ip uint32
		var port uint16
		if err := rows.Scan(&id, &hostname, &ip, &port); err != nil {
			continue
		}

		host, portStr, _ := net.SplitHostPort(hostname)
		if host == "" {
			host = hostname
		}

		if host == containerName {
			return id, ip, port, portStr, nil
		}
	}

	return 0, 0, 0, "", fmt.Errorf("not found")
}
