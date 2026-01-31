package main

import (
	"Aegis/controller/config"
	"Aegis/controller/database"
	"Aegis/controller/internal/utils"
	"Aegis/controller/proto"
	"Aegis/controller/server"
	"fmt"
	"log"
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
	go server.StartServer(cfg.ServerPort, cfg.CertFile, cfg.KeyFile)

	err := proto.Init(cfg.AgentAddress, cfg.AgentCertFile, cfg.AgentKeyFile, cfg.AgentCAFile, cfg.AgentServerName)
	if err != nil {
		log.Printf("[ERROR] Error starting grpc client: %v", err)
		return
	}

	go func() {
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
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	// Block until a signal is received.
	<-quit

	log.Println("[INFO] Interrupt signal received. Shutting down server...")
}
