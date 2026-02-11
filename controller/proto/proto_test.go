package proto

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// mockSessionManagerClient is a mock implementation of SessionManagerClient
type mockSessionManagerClient struct{}

func (m *mockSessionManagerClient) SubmitSession(ctx context.Context, in *LoginEvent, opts ...grpc.CallOption) (*Ack, error) {
	return &Ack{Success: true}, nil
}

func (m *mockSessionManagerClient) MonitorSessions(ctx context.Context, in *Empty, opts ...grpc.CallOption) (grpc.ServerStreamingClient[SessionList], error) {
	return nil, nil
}

func (m *mockSessionManagerClient) IpChange(ctx context.Context, in *IpChangeList, opts ...grpc.CallOption) (*Ack, error) {
	return nil, fmt.Errorf("mock error: agent not running")
}

func TestSendChangedIpData(t *testing.T) {
	c = &mockSessionManagerClient{}

	tests := []struct {
		name      string
		ipChanges []*IpChangeEvent
		wantErr   bool
	}{
		{
			name: "single IP change",
			ipChanges: []*IpChangeEvent{
				{
					OldIp: 0x0A000001, // 10.0.0.1
					NewIp: 0x0A000002, // 10.0.0.2
				},
			},
			wantErr: true, // Should error because mock returns error
		},
		{
			name: "multiple IP changes",
			ipChanges: []*IpChangeEvent{
				{
					OldIp: 0x0A000001, // 10.0.0.1
					NewIp: 0x0A000002, // 10.0.0.2
				},
				{
					OldIp: 0x0A000003, // 10.0.0.3
					NewIp: 0x0A000004, // 10.0.0.4
				},
			},
			wantErr: true, // Should error because mock returns error
		},
		{
			name:      "empty IP change list",
			ipChanges: []*IpChangeEvent{},
			wantErr:   true, // Should error because mock returns error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changedIps := &IpChangeList{
				IpChanges: tt.ipChanges,
			}

			_, err := SendChanedIpData(changedIps, time.Second)

			if (err != nil) != tt.wantErr {
				t.Errorf("SendChanedIpData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIpChangeListCreation(t *testing.T) {
	t.Run("create empty list", func(t *testing.T) {
		list := &IpChangeList{
			IpChanges: []*IpChangeEvent{},
		}
		if len(list.IpChanges) != 0 {
			t.Errorf("expected empty list, got %d items", len(list.IpChanges))
		}
	})

	t.Run("create list with events", func(t *testing.T) {
		list := &IpChangeList{
			IpChanges: []*IpChangeEvent{
				{OldIp: 0x0A000001, NewIp: 0x0A000002},
				{OldIp: 0x0A000003, NewIp: 0x0A000004},
			},
		}
		if len(list.IpChanges) != 2 {
			t.Errorf("expected 2 items, got %d", len(list.IpChanges))
		}
	})
}

func TestIpChangeEvent(t *testing.T) {
	t.Run("create IP change event", func(t *testing.T) {
		event := &IpChangeEvent{
			OldIp: 0x0A000001, // 10.0.0.1
			NewIp: 0x0A000002, // 10.0.0.2
		}
		if event.OldIp != 0x0A000001 {
			t.Errorf("expected OldIp 0x0A000001, got 0x%08X", event.OldIp)
		}
		if event.NewIp != 0x0A000002 {
			t.Errorf("expected NewIp 0x0A000002, got 0x%08X", event.NewIp)
		}
	})

	t.Run("IP values are preserved", func(t *testing.T) {
		testCases := []struct {
			oldIp uint32
			newIp uint32
		}{
			{0x7F000001, 0x7F000002}, // 127.0.0.1 -> 127.0.0.2
			{0xC0A80001, 0xC0A80002}, // 192.168.0.1 -> 192.168.0.2
			{0x0A000001, 0x0A000002}, // 10.0.0.1 -> 10.0.0.2
		}

		for _, tc := range testCases {
			event := &IpChangeEvent{
				OldIp: tc.oldIp,
				NewIp: tc.newIp,
			}
			if event.OldIp != tc.oldIp {
				t.Errorf("OldIp not preserved: expected 0x%08X, got 0x%08X", tc.oldIp, event.OldIp)
			}
			if event.NewIp != tc.newIp {
				t.Errorf("NewIp not preserved: expected 0x%08X, got 0x%08X", tc.newIp, event.NewIp)
			}
		}
	})
}
