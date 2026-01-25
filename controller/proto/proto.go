package proto

import (
	"Aegis/controller/internal/utils"
	"context"
	"io"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var c SessionManagerClient

func Init() error {
	conn, err := grpc.NewClient("172.21.0.10:50001", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	c = NewSessionManagerClient(conn)
	return nil
}

// SendSessionData sends a login event to the server
func SendSessionData(srcIp, dstIp string, port uint32, active bool) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
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

	log.Println("Started monitoring sessions...")

	for {
		// This blocks until the server sends data (every 5 seconds as per your server logic)
		sessionList, err := stream.Recv()
		if err == io.EOF {
			log.Println("Server closed the stream.")
			break
		}
		if err != nil {
			log.Printf("stream error: %v", err)
			break
		}

		// Execute the provided callback with the received list [cite: 5]
		callback(sessionList)
	}

	return nil
}
