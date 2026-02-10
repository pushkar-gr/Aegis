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
	serviceID, currentIPPort, servicePort, err := findServiceByHostnamePrefix(containerName)
	if err != nil {
		return
	}

	json, err := cli.ContainerInspect(context.Background(), msg.ID)
	if err != nil {
		log.Printf("[WARN] Docker watcher: failed to inspect container %s: %v", containerName, err)
		return
	}

	// Extract IP address
	var newIP string
	for _, network := range json.NetworkSettings.Networks {
		if network.IPAddress != "" {
			newIP = network.IPAddress
			break
		}
	}

	if newIP == "" {
		log.Printf("[WARN] Docker watcher: container %s started but has no IP", containerName)
		return
	}

	newIPPort := net.JoinHostPort(newIP, servicePort)

	if newIPPort != currentIPPort {
		log.Printf("[INFO] Docker Event: Container '%s' started. Updating Service %d IP: %s -> %s",
			containerName, serviceID, currentIPPort, newIPPort)

		_, err := database.DB.Exec("UPDATE services SET ip_port = ? WHERE id = ?", newIPPort, serviceID)
		if err != nil {
			log.Printf("[ERROR] Docker watcher: failed to update DB: %v", err)
		}
	}
}

// findServiceByHostnamePrefix checks if any registered service matches the container name.
func findServiceByHostnamePrefix(containerName string) (int, string, string, error) {
	rows, err := database.DB.Query("SELECT id, hostname, ip_port FROM services")
	if err != nil {
		return 0, "", "", err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var id int
		var hostname, ipPort string
		if err := rows.Scan(&id, &hostname, &ipPort); err != nil {
			continue
		}

		host, port, _ := net.SplitHostPort(hostname)
		if host == "" {
			host = hostname
		}

		if host == containerName {
			return id, ipPort, port, nil
		}
	}

	return 0, "", "", fmt.Errorf("not found")
}
