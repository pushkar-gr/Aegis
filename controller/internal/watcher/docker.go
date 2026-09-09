package watcher

import (
	"Aegis/controller/internal/repository"
	"Aegis/controller/internal/utils"
	"Aegis/controller/proto"
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const (
	baseRetryDelay = 2 * time.Second
	maxRetryDelay  = 60 * time.Second
	resetThreshold = 30 * time.Second
)

// StartDockerWatcher listens for container events and updates service IPs in realtime
func StartDockerWatcher(agentCallTimeout time.Duration) {
	delay := baseRetryDelay
	for {
		start := time.Now()
		connected := runDockerWatcherOnce(agentCallTimeout)
		ran := time.Since(start)

		if ran > resetThreshold {
			delay = baseRetryDelay
		} else {
			delay *= 2
			if delay > maxRetryDelay {
				delay = maxRetryDelay
			}
		}

		if !connected {
			log.Printf("[WARN] Docker watcher: retrying in %v (relying on DNS polling in the meantime)", delay)
		} else {
			log.Printf("[WARN] Docker watcher: event stream disconnected, reconnecting in %v", delay)
		}
		time.Sleep(delay)
	}
}

func runDockerWatcherOnce(agentCallTimeout time.Duration) (connected bool) {
	// Initialize Docker Client
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("[WARN] Docker watcher: failed to create client: %v", err)
		return false
	}
	defer func() { _ = cli.Close() }()

	// Verify connection
	if _, err := cli.Ping(context.Background()); err != nil {
		log.Printf("[WARN] Docker watcher: cannot connect to Docker socket: %v", err)
		return false
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
			return true
		case msg := <-msgChan:
			handleContainerEvent(cli, msg, agentCallTimeout)
		}
	}
}

// handleContainerEvent hanles a container event by getting its hostname and checking with existing hostnames, if found it will udpate the ip
func handleContainerEvent(cli *client.Client, msg events.Message, agentCallTimeout time.Duration) {
	containerName := msg.Actor.Attributes["name"]
	if containerName == "" {
		return
	}

	// Check if there is any service using the container name as a hostname
	serviceID, currentIP, currentPort, servicePort, err := findServiceByHostnamePrefix(containerName)
	if err != nil {
		return
	}

	json, err := cli.ContainerInspect(context.Background(), msg.Actor.ID)
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
	newIP := utils.IpToUint32(newIPStr)

	// Parse port
	portNum, err := net.LookupPort("tcp", servicePort)
	if err != nil {
		log.Printf("[WARN] Docker watcher: invalid port %s: %v", servicePort, err)
		return
	}
	newPort := uint16(portNum)

	if newIP != currentIP || newPort != currentPort {
		currentIPStr := utils.Uint32ToIp(currentIP)
		log.Printf("[INFO] Docker Event: Container '%s' started. Updating Service %d IP: %s:%d -> %s:%d",
			containerName, serviceID, currentIPStr, currentPort, newIPStr, newPort)

		if _, err := repository.DB.Exec("UPDATE services SET ip = ?, port = ? WHERE id = ?", newIP, newPort, serviceID); err != nil {
			log.Printf("[ERROR] Docker watcher: failed to update DB: %v", err)
			return
		}

		if newIP != currentIP {
			changedIps := &proto.IpChangeList{
				IpChanges: []*proto.IpChangeEvent{{OldIp: currentIP, NewIp: newIP}},
			}
			success, err := proto.SendChanedIpData(changedIps, agentCallTimeout)
			if err != nil {
				log.Printf("[ERROR] Docker watcher: failed to notify agent of IP change for service %d: %v", serviceID, err)
			} else if !success {
				log.Printf("[ERROR] Docker watcher: agent did not acknowledge IP change for service %d", serviceID)
			}
		}
	}
}

// findServiceByHostnamePrefix checks if any registered service matches the container name.
func findServiceByHostnamePrefix(containerName string) (int, uint32, uint16, string, error) {
	pattern := containerName + ":%"
	rows, err := repository.DB.Query("SELECT id, hostname, ip, port FROM services WHERE hostname LIKE ?", pattern)
	if err != nil {
		return 0, 0, 0, "", fmt.Errorf("query failed: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var id int
		var hostname string
		var ip uint32
		var port uint16
		if err := rows.Scan(&id, &hostname, &ip, &port); err != nil {
			log.Printf("[WARN] Docker watcher: failed to scan service row: %v", err)
			continue
		}

		host, portStr, err := net.SplitHostPort(hostname)
		if err != nil {
			log.Printf("[WARN] Docker watcher: invalid hostname format '%s': %v", hostname, err)
			continue
		}

		if host == containerName {
			return id, ip, port, portStr, nil
		}
	}

	return 0, 0, 0, "", fmt.Errorf("service not found for container: %s", containerName)
}
