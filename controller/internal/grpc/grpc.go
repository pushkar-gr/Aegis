package grpc

import (
	"Aegis/controller/internal/repository"
	"Aegis/controller/internal/utils"
	"Aegis/controller/proto"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	baseDelay      = 1 * time.Second
	maxDelay       = 60 * time.Second
	resetThreshold = 10 * time.Second
)

// SessionConfig holds config for the session manager.
type SessionConfig struct {
	IpUpdateInterval time.Duration
}

// SessionManager monitors gRPC streams and keeps session in sync.
type SessionManager struct {
	svcRepo  repository.ServiceRepository
	userRepo repository.UserRepository
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(svcRepo repository.ServiceRepository, userRepo repository.UserRepository) *SessionManager {
	return &SessionManager{svcRepo: svcRepo, userRepo: userRepo}
}

// Start launches all background goroutines.
func (m *SessionManager) Start(cfg SessionConfig) {
	go m.connectGrpc()
	go m.updateIpFromHostnames(cfg.IpUpdateInterval)
	go m.cleanupExpiredTokens()
}

func (m *SessionManager) cleanupExpiredTokens() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		if err := m.userRepo.CleanupExpiredRefreshTokens(); err != nil {
			log.Printf("[ERROR] Failed to cleanup expired refresh tokens: %v", err)
		} else {
			log.Printf("[INFO] Cleaned up expired refresh tokens")
		}
	}
}

func (m *SessionManager) connectGrpc() {
	currentDelay := baseDelay
	for {
		connectStartTime := time.Now()

		err := proto.MonitorStream(func(list *proto.SessionList) {
			log.Printf("[INFO] Received update with %d sessions", len(list.Sessions))

			serviceMap, err := m.svcRepo.GetServiceMap()
			if err != nil {
				log.Printf("[ERROR] Sync skipped: failed to get service map: %v", err)
				return
			}

			activeUsersMap, err := m.svcRepo.GetActiveServiceUsers()
			if err != nil {
				log.Printf("[ERROR] Sync skipped: failed to get active users: %v", err)
				return
			}

			type key struct{ uID, sID int }
			syncMap := make(map[key]int)

			for _, s := range list.Sessions {
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

			sessionsToSync := make([]repository.ActiveSessionSync, 0, len(syncMap))
			for k, timeLeft := range syncMap {
				sessionsToSync = append(sessionsToSync, repository.ActiveSessionSync{
					UserID: k.uID, ServiceID: k.sID, TimeLeft: timeLeft,
				})
			}

			if err := m.svcRepo.SyncActiveSessions(sessionsToSync); err != nil {
				log.Printf("[ERROR] Error syncing active sessions to DB: %v", err)
			} else {
				log.Printf("[INFO] Synced %d active sessions to database", len(sessionsToSync))
			}
		})

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

func (m *SessionManager) updateIpFromHostnames(updateInterval time.Duration) {
	m.syncHostnameIPs()
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()
	for range ticker.C {
		m.syncHostnameIPs()
	}
}

func (m *SessionManager) syncHostnameIPs() {
	changedIps := &proto.IpChangeList{IpChanges: []*proto.IpChangeEvent{}}

	services, err := m.svcRepo.ListForIPSync()
	if err != nil {
		log.Printf("[ERROR] updateHostnames: failed to query services: %v", err)
		return
	}

	for _, s := range services {
		host, port, err := net.SplitHostPort(s.Hostname)
		if err != nil {
			log.Printf("[WARN] updateHostnames: invalid hostname format for service ID %d (%s): %v", s.ID, s.Hostname, err)
			continue
		}

		var resolvedIP string
		if ip := net.ParseIP(host); ip != nil {
			resolvedIP = host
		} else {
			ips, err := utils.ResolveHostname(host)
			if err != nil || len(ips) == 0 {
				log.Printf("[WARN] updateHostnames: failed to resolve %s for service ID %d: %v", host, s.ID, err)
				continue
			}
			resolvedIP = ips[0]
		}

		newIpInt := utils.IpToUint32(resolvedIP)
		portNum, err := net.LookupPort("tcp", port)
		if err != nil {
			log.Printf("[WARN] updateHostnames: invalid port %s for service ID %d: %v", port, s.ID, err)
			continue
		}
		newPort := uint16(portNum)

		if newIpInt != s.CurrentIP || newPort != s.CurrentPort {
			oldIpStr := utils.Uint32ToIp(s.CurrentIP)
			log.Printf("[INFO] Service %d (%s) changed: %s:%d -> %s:%d. Updating DB.",
				s.ID, s.Hostname, oldIpStr, s.CurrentPort, resolvedIP, newPort)

			if err := m.svcRepo.UpdateIPPort(s.ID, newIpInt, newPort); err != nil {
				log.Printf("[ERROR] updateHostnames: failed to update service ID %d: %v", s.ID, err)
			}

			if s.CurrentIP != newIpInt {
				changedIps.IpChanges = append(changedIps.IpChanges, &proto.IpChangeEvent{
					OldIp: s.CurrentIP,
					NewIp: newIpInt,
				})
			}
		}
	}

	if len(changedIps.IpChanges) > 0 {
		success, err := proto.SendChanedIpData(changedIps, time.Second)
		if err != nil {
			log.Printf("[ERROR] updateHostnames: failed to update IPs in agent: %v", err)
		}
		if success {
			log.Printf("[INFO] updateHostnames: updated %d IPs in agent", len(changedIps.IpChanges))
		} else {
			log.Printf("[ERROR] updateHostnames: failed to update IPs in agent")
		}
	}
}
