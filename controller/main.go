package main

import (
	"Aegis/controller/config"
	"Aegis/controller/database"
	"Aegis/controller/internal/utils"
	"Aegis/controller/internal/watcher"
	"Aegis/controller/proto"
	"Aegis/controller/server"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"
)

// Backoff configuration
const (
	baseDelay      = 1 * time.Second
	maxDelay       = 60 * time.Second
	resetThreshold = 10 * time.Second
)

// main initializes the database, starts the HTTP server in a separate goroutine,
// and handles graceful shutdown upon receiving an interrupt signal.
func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize the SQLite database connection and schema.
	database.InitDB(cfg.MaxOpenConns, cfg.MaxIdleConns, cfg.ConnMaxLifetime)
	defer func() {
		if err := database.DB.Close(); err != nil {
			log.Printf("[ERROR] Error closing database: %v", err)
		}
	}()
	// Start the server in a goroutine so the main thread can listen for signals.
	go server.StartServer(cfg.ServerPort, cfg.CertFile, cfg.KeyFile, []byte(cfg.JwtKey), cfg.JwtTokenLifetime)

	err := proto.Init(cfg.AgentAddress, cfg.AgentCertFile, cfg.AgentKeyFile, cfg.AgentCAFile, cfg.AgentServerName)
	if err != nil {
		log.Printf("[ERROR] Error starting grpc client: %v", err)
		return
	}

	go connectGrpc()
	go updateIpFromHostnames(cfg.IpUpdateInterval)
	go watcher.StartDockerWatcher()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	// Block until a signal is received.
	<-quit

	log.Println("[INFO] Interrupt signal received. Shutting down server...")
}

// Connects to gRPC server, pushes updates and listenes to stale updates from agent
func connectGrpc() {
	currentDelay := baseDelay
	for {
		connectStartTime := time.Now()

		err := proto.MonitorStream(func(list *proto.SessionList) {
			log.Printf("[INFO] Received update with %d sessions", len(list.Sessions))

			// Fetch current mappings from DB to resolve IDs
			serviceMap, err := database.GetServiceMap()
			if err != nil {
				log.Printf("[ERROR] Sync skipped: failed to get service map: %v", err)
				return
			}

			activeUsersMap, err := database.GetActiveServiceUsers()
			if err != nil {
				log.Printf("[ERROR] Sync skipped: failed to get active users: %v", err)
				return
			}

			// Prepare the list of sessions to keep/update
			type key struct {
				uID int
				sID int
			}
			syncMap := make(map[key]int)

			for _, s := range list.Sessions {
				// Format BPF Dst IP:Port to match DB "ip:port" string
				dstIpStr := utils.Uint32ToIp(s.DstIp)
				serviceKey := fmt.Sprintf("%s:%d", dstIpStr, s.DstPort)

				if svcID, ok := serviceMap[serviceKey]; ok {
					if userIDs, exists := activeUsersMap[svcID]; exists {
						for _, uID := range userIDs {
							k := key{uID, svcID}
							if t, exists := syncMap[k]; !exists || int(s.TimeLeft) > t {
								syncMap[k] = int(s.TimeLeft)
							}
						}
					}
				} else {
					log.Printf("[WARN] Unknown service traffic %s", serviceKey)
				}
			}

			// Convert map to slice for the DB transaction
			sessionsToSync := make([]database.ActiveSessionSync, 0, len(syncMap))
			for k, timeLeft := range syncMap {
				sessionsToSync = append(sessionsToSync, database.ActiveSessionSync{
					UserID:    k.uID,
					ServiceID: k.sID,
					TimeLeft:  timeLeft,
				})
			}

			// Perform the Sync (Update existing, Delete missing)
			if err := database.SyncActiveSessions(sessionsToSync); err != nil {
				log.Printf("[ERROR] Error syncing active sessions to DB: %v", err)
			} else {
				log.Printf("[INFO] Synced %d active sessions to database", len(sessionsToSync))
			}

		})

		// Stream exited
		connectionDuration := time.Since(connectStartTime)

		if err != nil {
			log.Printf("[ERROR] MonitorStream disconnected: %v", err)
		} else {
			log.Println("[WARN] MonitorStream closed cleanly (EOF), reconnecting...")
		}
		if connectionDuration > resetThreshold {
			currentDelay = baseDelay
			log.Println("[INFO] Connection was stable. Resetting backoff.")
		} else {
			currentDelay *= 2
			if currentDelay > maxDelay {
				currentDelay = maxDelay
			}
		}
		log.Printf("[INFO] Reconnecting in %v...", currentDelay)
		time.Sleep(currentDelay)
	}
}

// updateIpFromHostnames handles the scheduling of the hostname sync
func updateIpFromHostnames(updateIpIterval time.Duration) {
	// Run immediately on startup
	syncHostnameIPs()

	// Schedule to run every `updateIpIterval`
	ticker := time.NewTicker(updateIpIterval)
	defer ticker.Stop()

	for range ticker.C {
		syncHostnameIPs()
	}
}

// syncHostnameIPs updates IP addresses of all entries in the services table periodically
func syncHostnameIPs() {
	changedIps := &proto.IpChangeList{
		IpChanges: []*proto.IpChangeEvent{},
	}

	// Query all services
	rows, err := database.DB.Query("SELECT id, hostname, ip_port FROM services")
	if err != nil {
		log.Printf("[ERROR] updateHostnames: failed to query services: %v", err)
		return
	}

	type svcData struct {
		id            int
		hostname      string
		currentIPPort string
	}
	var services []svcData

	// Read all rows
	for rows.Next() {
		var s svcData
		if err := rows.Scan(&s.id, &s.hostname, &s.currentIPPort); err != nil {
			log.Printf("[ERROR] updateHostnames: scan error: %v", err)
			continue
		}
		services = append(services, s)
	}
	defer func() { _ = rows.Close() }()

	// Process all service
	for _, s := range services {
		host, port, err := net.SplitHostPort(s.hostname)
		if err != nil {
			log.Printf("[WARN] updateHostnames: invalid hostname format for service ID %d (%s): %v", s.id, s.hostname, err)
			continue
		}

		var resolvedIP string
		// Check if host is already an IP
		if ip := net.ParseIP(host); ip != nil {
			resolvedIP = host
		} else {
			// Resolve DNS
			ips, err := utils.ResolveHostname(host)
			if err != nil || len(ips) == 0 {
				log.Printf("[WARN] updateHostnames: failed to resolve %s for service ID %d: %v", host, s.id, err)
				continue
			}
			resolvedIP = ips[0]
		}

		newIPPort := net.JoinHostPort(resolvedIP, port)

		// Update DB if different
		if newIPPort != s.currentIPPort {
			log.Printf("[INFO] Service %d (%s) IP changed: %s -> %s. Updating DB.", s.id, s.hostname, s.currentIPPort, newIPPort)

			_, err := database.DB.Exec("UPDATE services SET ip_port = ? WHERE id = ?", newIPPort, s.id)
			if err != nil {
				log.Printf("[ERROR] updateHostnames: failed to update service ID %d: %v", s.id, err)
			}

			oldHost, _, _ := net.SplitHostPort(s.currentIPPort)
			oldIpInt := utils.IpToUint32(oldHost)
			newIpInt := utils.IpToUint32(resolvedIP)
			changedIps.IpChanges = append(changedIps.IpChanges, &proto.IpChangeEvent{
				OldIp: oldIpInt,
				NewIp: newIpInt,
			})
		}
	}

	success, err := proto.SendChanedIpData(changedIps, time.Second)
	if err != nil {
		log.Printf("[ERROR] updateHostnames: failed to update IPs in agent: %v", err)
	}
	log.Println(changedIps)
	if success {
		log.Printf("[INFO] updateHostnames: updated IPs in agent")
	} else {
		log.Printf("[ERROR] updateHostnames: failed to update IPs in agent")
	}
}
