package proto

import (
	"Aegis/controller/internal/utils"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var c SessionManagerClient

func Init(agentAddr, certFile, keyFile, caFile, serverName string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load client cert/key: %v", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return fmt.Errorf("failed to append CA cert")
	}

	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   serverName,
	})

	conn, err := grpc.NewClient(agentAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	c = NewSessionManagerClient(conn)
	return nil
}

// SendSessionData sends a login event to the server
func SendSessionData(srcIp, dstIp string, port uint32, active bool, timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req := &LoginEvent{
		SrcIp:    utils.IpToUint32(srcIp),
		DstIp:    utils.IpToUint32(dstIp),
		DstPort:  port,
		Activate: active,
	}

	res, err := c.SubmitSession(ctx, req)
	if err != nil {
		return false, err
	}
	return res.GetSuccess(), nil
}

// MonitorStream listens to the server stream and executes a callback for each update
func MonitorStream(callback func(*SessionList)) error {
	// Use context.Background() since this stream should run indefinitely
	stream, err := c.MonitorSessions(context.Background(), &Empty{})
	if err != nil {
		return err
	}

	log.Println("[INFO] Started monitoring sessions...")

	for {
		// This blocks until the server sends data (every 5 seconds as per your server logic)
		sessionList, err := stream.Recv()
		if err == io.EOF {
			log.Println("[INFO] Server closed the stream.")
			break
		}
		if err != nil {
			log.Printf("[ERROR] stream error: %v", err)
			break
		}

		// Execute the provided callback with the received list [cite: 5]
		callback(sessionList)
	}

	return nil
}
