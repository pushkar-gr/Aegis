package main

import (
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

// main initializes the database, starts the HTTP server in a separate goroutine,
// and handles graceful shutdown upon receiving an interrupt signal.
func main() {
	// Initialize the SQLite database connection and schema.
	database.InitDB()
	defer func() {
		if err := database.DB.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()
	// Start the server in a goroutine so the main thread can listen for signals.
	go server.StartServer()

	err := proto.Init()
	if err != nil {
		log.Printf("Error starting grpc server: %v", err)
		return
	}

	go func() {
		for {
			if err := proto.MonitorStream(func(list *proto.SessionList) {
				log.Printf("Received update with %d sessions", len(list.Sessions))

				// Fetch current mappings from DB to resolve IDs
				serviceMap, err := database.GetServiceMap() // ip:port -> id
				if err != nil {
					log.Printf("Sync skipped: failed to get service map: %v", err)
					return
				}

				activeUsersMap, err := database.GetActiveServiceUsers() // service_id -> []user_id
				if err != nil {
					log.Printf("Sync skipped: failed to get active users: %v", err)
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
						log.Printf("Warning: Unknown service traffic %s", serviceKey)
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
					log.Printf("Error syncing active sessions to DB: %v", err)
				} else {
					log.Printf("Synced %d active sessions to database", len(sessionsToSync))
				}

			}); err != nil {
				log.Printf("MonitorStream stopped with error: %v\nRetrying in 5 secs", err)
				time.Sleep(5 * time.Second)
			}
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	// Block until a signal is received.
	<-quit

	log.Println("Interrupt signal received. Shutting down server...")
}
